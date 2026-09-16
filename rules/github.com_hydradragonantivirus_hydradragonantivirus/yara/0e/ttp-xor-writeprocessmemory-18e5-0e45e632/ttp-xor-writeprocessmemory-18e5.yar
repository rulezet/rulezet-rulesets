rule TTP_XOR_WriteProcessMemory_18e5 {
  strings:
    $key_18e5 = { 4f 97 [2] 7d b5 [2] 7b 80 [2] 55 80 [2] 6a 9c }

  condition:
    any of them
}