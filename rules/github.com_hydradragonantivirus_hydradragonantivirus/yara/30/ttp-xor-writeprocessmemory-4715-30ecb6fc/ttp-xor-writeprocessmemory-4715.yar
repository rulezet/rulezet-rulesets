rule TTP_XOR_WriteProcessMemory_4715 {
  strings:
    $key_4715 = { 10 67 [2] 22 45 [2] 24 70 [2] 0a 70 [2] 35 6c }

  condition:
    any of them
}