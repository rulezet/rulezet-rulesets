rule TTP_XOR_WriteProcessMemory_c402 {
  strings:
    $key_c402 = { 93 70 [2] a1 52 [2] a7 67 [2] 89 67 [2] b6 7b }

  condition:
    any of them
}