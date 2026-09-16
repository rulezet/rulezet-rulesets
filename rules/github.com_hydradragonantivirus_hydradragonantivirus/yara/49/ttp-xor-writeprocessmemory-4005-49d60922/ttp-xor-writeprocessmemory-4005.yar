rule TTP_XOR_WriteProcessMemory_4005 {
  strings:
    $key_4005 = { 17 77 [2] 25 55 [2] 23 60 [2] 0d 60 [2] 32 7c }

  condition:
    any of them
}