rule TTP_XOR_WriteProcessMemory_2f05 {
  strings:
    $key_2f05 = { 78 77 [2] 4a 55 [2] 4c 60 [2] 62 60 [2] 5d 7c }

  condition:
    any of them
}