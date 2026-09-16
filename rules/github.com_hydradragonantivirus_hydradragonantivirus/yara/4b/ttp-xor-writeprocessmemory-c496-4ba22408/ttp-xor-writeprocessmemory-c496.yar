rule TTP_XOR_WriteProcessMemory_c496 {
  strings:
    $key_c496 = { 93 e4 [2] a1 c6 [2] a7 f3 [2] 89 f3 [2] b6 ef }

  condition:
    any of them
}