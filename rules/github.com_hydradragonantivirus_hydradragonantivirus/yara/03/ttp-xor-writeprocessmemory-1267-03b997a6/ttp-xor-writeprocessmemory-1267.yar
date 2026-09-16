rule TTP_XOR_WriteProcessMemory_1267 {
  strings:
    $key_1267 = { 45 15 [2] 77 37 [2] 71 02 [2] 5f 02 [2] 60 1e }

  condition:
    any of them
}