rule TTP_XOR_WriteProcessMemory_64e7 {
  strings:
    $key_64e7 = { 33 95 [2] 01 b7 [2] 07 82 [2] 29 82 [2] 16 9e }

  condition:
    any of them
}