rule TTP_XOR_WriteProcessMemory_1825 {
  strings:
    $key_1825 = { 4f 57 [2] 7d 75 [2] 7b 40 [2] 55 40 [2] 6a 5c }

  condition:
    any of them
}