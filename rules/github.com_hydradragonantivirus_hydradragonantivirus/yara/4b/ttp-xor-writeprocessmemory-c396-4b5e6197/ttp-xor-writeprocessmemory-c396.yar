rule TTP_XOR_WriteProcessMemory_c396 {
  strings:
    $key_c396 = { 94 e4 [2] a6 c6 [2] a0 f3 [2] 8e f3 [2] b1 ef }

  condition:
    any of them
}