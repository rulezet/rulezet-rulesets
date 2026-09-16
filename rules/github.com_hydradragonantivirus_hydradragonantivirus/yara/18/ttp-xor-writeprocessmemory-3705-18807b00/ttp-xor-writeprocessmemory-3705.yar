rule TTP_XOR_WriteProcessMemory_3705 {
  strings:
    $key_3705 = { 60 77 [2] 52 55 [2] 54 60 [2] 7a 60 [2] 45 7c }

  condition:
    any of them
}