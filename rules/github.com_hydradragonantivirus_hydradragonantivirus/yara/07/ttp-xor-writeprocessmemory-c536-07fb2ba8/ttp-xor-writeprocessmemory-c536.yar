rule TTP_XOR_WriteProcessMemory_c536 {
  strings:
    $key_c536 = { 92 44 [2] a0 66 [2] a6 53 [2] 88 53 [2] b7 4f }

  condition:
    any of them
}