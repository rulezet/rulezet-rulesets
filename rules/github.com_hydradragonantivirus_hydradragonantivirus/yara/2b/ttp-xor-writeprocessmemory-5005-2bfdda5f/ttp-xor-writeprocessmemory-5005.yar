rule TTP_XOR_WriteProcessMemory_5005 {
  strings:
    $key_5005 = { 07 77 [2] 35 55 [2] 33 60 [2] 1d 60 [2] 22 7c }

  condition:
    any of them
}