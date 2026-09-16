rule TTP_XOR_WriteProcessMemory_38e7 {
  strings:
    $key_38e7 = { 6f 95 [2] 5d b7 [2] 5b 82 [2] 75 82 [2] 4a 9e }

  condition:
    any of them
}