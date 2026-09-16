rule TTP_XOR_WriteProcessMemory_1615 {
  strings:
    $key_1615 = { 41 67 [2] 73 45 [2] 75 70 [2] 5b 70 [2] 64 6c }

  condition:
    any of them
}