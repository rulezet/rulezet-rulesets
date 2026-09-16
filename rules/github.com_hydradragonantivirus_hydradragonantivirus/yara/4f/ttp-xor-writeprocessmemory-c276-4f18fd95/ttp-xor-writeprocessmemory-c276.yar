rule TTP_XOR_WriteProcessMemory_c276 {
  strings:
    $key_c276 = { 95 04 [2] a7 26 [2] a1 13 [2] 8f 13 [2] b0 0f }

  condition:
    any of them
}