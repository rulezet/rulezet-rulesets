rule TTP_XOR_WriteProcessMemory_2775 {
  strings:
    $key_2775 = { 70 07 [2] 42 25 [2] 44 10 [2] 6a 10 [2] 55 0c }

  condition:
    any of them
}