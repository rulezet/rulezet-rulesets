rule TTP_XOR_WriteProcessMemory_c314 {
  strings:
    $key_c314 = { 94 66 [2] a6 44 [2] a0 71 [2] 8e 71 [2] b1 6d }

  condition:
    any of them
}