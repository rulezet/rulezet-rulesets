rule TTP_XOR_WriteProcessMemory_1d67 {
  strings:
    $key_1d67 = { 4a 15 [2] 78 37 [2] 7e 02 [2] 50 02 [2] 6f 1e }

  condition:
    any of them
}