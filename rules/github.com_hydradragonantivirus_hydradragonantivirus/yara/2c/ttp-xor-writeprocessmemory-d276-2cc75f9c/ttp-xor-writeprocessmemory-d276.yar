rule TTP_XOR_WriteProcessMemory_d276 {
  strings:
    $key_d276 = { 85 04 [2] b7 26 [2] b1 13 [2] 9f 13 [2] a0 0f }

  condition:
    any of them
}