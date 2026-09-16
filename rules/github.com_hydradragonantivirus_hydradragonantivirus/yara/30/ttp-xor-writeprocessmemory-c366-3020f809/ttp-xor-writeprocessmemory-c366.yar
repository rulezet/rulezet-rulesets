rule TTP_XOR_WriteProcessMemory_c366 {
  strings:
    $key_c366 = { 94 14 [2] a6 36 [2] a0 03 [2] 8e 03 [2] b1 1f }

  condition:
    any of them
}