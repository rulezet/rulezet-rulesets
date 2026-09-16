rule TTP_XOR_WriteProcessMemory_4a67 {
  strings:
    $key_4a67 = { 1d 15 [2] 2f 37 [2] 29 02 [2] 07 02 [2] 38 1e }

  condition:
    any of them
}