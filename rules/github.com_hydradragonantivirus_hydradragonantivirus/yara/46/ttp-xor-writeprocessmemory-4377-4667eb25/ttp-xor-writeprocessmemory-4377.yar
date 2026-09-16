rule TTP_XOR_WriteProcessMemory_4377 {
  strings:
    $key_4377 = { 14 05 [2] 26 27 [2] 20 12 [2] 0e 12 [2] 31 0e }

  condition:
    any of them
}