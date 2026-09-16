rule TTP_XOR_WriteProcessMemory_c266 {
  strings:
    $key_c266 = { 95 14 [2] a7 36 [2] a1 03 [2] 8f 03 [2] b0 1f }

  condition:
    any of them
}