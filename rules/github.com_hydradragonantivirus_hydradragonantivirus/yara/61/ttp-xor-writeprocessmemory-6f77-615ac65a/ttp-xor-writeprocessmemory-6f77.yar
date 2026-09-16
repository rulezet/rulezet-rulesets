rule TTP_XOR_WriteProcessMemory_6f77 {
  strings:
    $key_6f77 = { 38 05 [2] 0a 27 [2] 0c 12 [2] 22 12 [2] 1d 0e }

  condition:
    any of them
}