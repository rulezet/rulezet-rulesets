rule TTP_XOR_WriteProcessMemory_5215 {
  strings:
    $key_5215 = { 05 67 [2] 37 45 [2] 31 70 [2] 1f 70 [2] 20 6c }

  condition:
    any of them
}