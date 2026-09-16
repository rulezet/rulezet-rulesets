rule TTP_XOR_WriteProcessMemory_1815 {
  strings:
    $key_1815 = { 4f 67 [2] 7d 45 [2] 7b 70 [2] 55 70 [2] 6a 6c }

  condition:
    any of them
}