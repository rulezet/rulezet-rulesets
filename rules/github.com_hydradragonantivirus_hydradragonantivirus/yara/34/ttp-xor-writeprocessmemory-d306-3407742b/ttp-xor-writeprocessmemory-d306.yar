rule TTP_XOR_WriteProcessMemory_d306 {
  strings:
    $key_d306 = { 84 74 [2] b6 56 [2] b0 63 [2] 9e 63 [2] a1 7f }

  condition:
    any of them
}