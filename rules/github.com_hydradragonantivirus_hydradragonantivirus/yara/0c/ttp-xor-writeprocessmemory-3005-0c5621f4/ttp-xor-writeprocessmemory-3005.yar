rule TTP_XOR_WriteProcessMemory_3005 {
  strings:
    $key_3005 = { 67 77 [2] 55 55 [2] 53 60 [2] 7d 60 [2] 42 7c }

  condition:
    any of them
}