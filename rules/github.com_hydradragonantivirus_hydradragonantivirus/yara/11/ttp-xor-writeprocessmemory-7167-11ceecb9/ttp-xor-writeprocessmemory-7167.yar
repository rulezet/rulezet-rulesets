rule TTP_XOR_WriteProcessMemory_7167 {
  strings:
    $key_7167 = { 26 15 [2] 14 37 [2] 12 02 [2] 3c 02 [2] 03 1e }

  condition:
    any of them
}