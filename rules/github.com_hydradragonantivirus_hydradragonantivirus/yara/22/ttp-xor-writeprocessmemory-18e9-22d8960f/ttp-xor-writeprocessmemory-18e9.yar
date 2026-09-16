rule TTP_XOR_WriteProcessMemory_18e9 {
  strings:
    $key_18e9 = { 4f 9b [2] 7d b9 [2] 7b 8c [2] 55 8c [2] 6a 90 }

  condition:
    any of them
}