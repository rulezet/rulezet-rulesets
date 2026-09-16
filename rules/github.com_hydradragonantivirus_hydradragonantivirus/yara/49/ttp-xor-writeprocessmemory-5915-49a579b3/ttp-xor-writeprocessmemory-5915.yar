rule TTP_XOR_WriteProcessMemory_5915 {
  strings:
    $key_5915 = { 0e 67 [2] 3c 45 [2] 3a 70 [2] 14 70 [2] 2b 6c }

  condition:
    any of them
}