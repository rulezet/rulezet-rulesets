rule TTP_XOR_WriteProcessMemory_5f05 {
  strings:
    $key_5f05 = { 08 77 [2] 3a 55 [2] 3c 60 [2] 12 60 [2] 2d 7c }

  condition:
    any of them
}