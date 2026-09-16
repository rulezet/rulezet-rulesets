rule TTP_XOR_WriteProcessMemory_d533 {
  strings:
    $key_d533 = { 82 41 [2] b0 63 [2] b6 56 [2] 98 56 [2] a7 4a }

  condition:
    any of them
}