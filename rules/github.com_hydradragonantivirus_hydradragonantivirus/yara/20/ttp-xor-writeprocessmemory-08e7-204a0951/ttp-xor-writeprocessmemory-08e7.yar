rule TTP_XOR_WriteProcessMemory_08e7 {
  strings:
    $key_08e7 = { 5f 95 [2] 6d b7 [2] 6b 82 [2] 45 82 [2] 7a 9e }

  condition:
    any of them
}