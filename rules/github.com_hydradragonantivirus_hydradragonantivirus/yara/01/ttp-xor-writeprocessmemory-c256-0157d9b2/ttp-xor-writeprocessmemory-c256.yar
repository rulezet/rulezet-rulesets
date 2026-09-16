rule TTP_XOR_WriteProcessMemory_c256 {
  strings:
    $key_c256 = { 95 24 [2] a7 06 [2] a1 33 [2] 8f 33 [2] b0 2f }

  condition:
    any of them
}