rule TTP_XOR_WriteProcessMemory_c492 {
  strings:
    $key_c492 = { 93 e0 [2] a1 c2 [2] a7 f7 [2] 89 f7 [2] b6 eb }

  condition:
    any of them
}