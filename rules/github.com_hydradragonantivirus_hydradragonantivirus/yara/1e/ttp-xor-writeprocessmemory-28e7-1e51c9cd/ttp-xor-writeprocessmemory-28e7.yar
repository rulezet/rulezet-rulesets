rule TTP_XOR_WriteProcessMemory_28e7 {
  strings:
    $key_28e7 = { 7f 95 [2] 4d b7 [2] 4b 82 [2] 65 82 [2] 5a 9e }

  condition:
    any of them
}