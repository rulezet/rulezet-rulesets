rule TTP_XOR_WriteProcessMemory_7405 {
  strings:
    $key_7405 = { 23 77 [2] 11 55 [2] 17 60 [2] 39 60 [2] 06 7c }

  condition:
    any of them
}