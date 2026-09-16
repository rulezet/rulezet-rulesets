rule TTP_XOR_WriteProcessMemory_3615 {
  strings:
    $key_3615 = { 61 67 [2] 53 45 [2] 55 70 [2] 7b 70 [2] 44 6c }

  condition:
    any of them
}