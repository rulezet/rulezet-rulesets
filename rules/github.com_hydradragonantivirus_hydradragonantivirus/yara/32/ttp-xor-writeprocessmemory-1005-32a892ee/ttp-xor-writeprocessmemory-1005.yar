rule TTP_XOR_WriteProcessMemory_1005 {
  strings:
    $key_1005 = { 47 77 [2] 75 55 [2] 73 60 [2] 5d 60 [2] 62 7c }

  condition:
    any of them
}