rule TTP_XOR_WriteProcessMemory_3715 {
  strings:
    $key_3715 = { 60 67 [2] 52 45 [2] 54 70 [2] 7a 70 [2] 45 6c }

  condition:
    any of them
}