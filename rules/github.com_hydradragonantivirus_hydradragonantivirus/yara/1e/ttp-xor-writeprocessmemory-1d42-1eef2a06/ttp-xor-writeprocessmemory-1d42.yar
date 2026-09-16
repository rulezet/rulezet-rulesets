rule TTP_XOR_WriteProcessMemory_1d42 {
  strings:
    $key_1d42 = { 4a 30 [2] 78 12 [2] 7e 27 [2] 50 27 [2] 6f 3b }

  condition:
    any of them
}