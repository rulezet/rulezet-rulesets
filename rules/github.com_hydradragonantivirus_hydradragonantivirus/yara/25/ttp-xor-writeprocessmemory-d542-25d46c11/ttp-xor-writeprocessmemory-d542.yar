rule TTP_XOR_WriteProcessMemory_d542 {
  strings:
    $key_d542 = { 82 30 [2] b0 12 [2] b6 27 [2] 98 27 [2] a7 3b }

  condition:
    any of them
}