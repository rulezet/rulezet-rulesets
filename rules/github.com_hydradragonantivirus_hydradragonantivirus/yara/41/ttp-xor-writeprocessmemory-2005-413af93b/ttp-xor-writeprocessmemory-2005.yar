rule TTP_XOR_WriteProcessMemory_2005 {
  strings:
    $key_2005 = { 77 77 [2] 45 55 [2] 43 60 [2] 6d 60 [2] 52 7c }

  condition:
    any of them
}