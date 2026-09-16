rule TTP_XOR_WriteProcessMemory_6367 {
  strings:
    $key_6367 = { 34 15 [2] 06 37 [2] 00 02 [2] 2e 02 [2] 11 1e }

  condition:
    any of them
}