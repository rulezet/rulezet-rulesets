rule TTP_XOR_WriteProcessMemory_1845 {
  strings:
    $key_1845 = { 4f 37 [2] 7d 15 [2] 7b 20 [2] 55 20 [2] 6a 3c }

  condition:
    any of them
}