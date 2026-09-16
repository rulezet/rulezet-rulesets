rule TTP_XOR_WriteProcessMemory_3405 {
  strings:
    $key_3405 = { 63 77 [2] 51 55 [2] 57 60 [2] 79 60 [2] 46 7c }

  condition:
    any of them
}