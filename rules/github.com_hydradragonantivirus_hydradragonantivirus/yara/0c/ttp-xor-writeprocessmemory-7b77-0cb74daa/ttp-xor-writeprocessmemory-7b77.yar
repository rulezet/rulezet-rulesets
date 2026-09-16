rule TTP_XOR_WriteProcessMemory_7b77 {
  strings:
    $key_7b77 = { 2c 05 [2] 1e 27 [2] 18 12 [2] 36 12 [2] 09 0e }

  condition:
    any of them
}