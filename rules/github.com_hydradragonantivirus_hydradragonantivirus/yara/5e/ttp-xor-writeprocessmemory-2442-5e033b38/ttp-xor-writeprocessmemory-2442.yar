rule TTP_XOR_WriteProcessMemory_2442 {
  strings:
    $key_2442 = { 73 30 [2] 41 12 [2] 47 27 [2] 69 27 [2] 56 3b }

  condition:
    any of them
}