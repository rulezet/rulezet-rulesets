rule TTP_XOR_WriteProcessMemory_8605 {
  strings:
    $key_8605 = { d1 77 [2] e3 55 [2] e5 60 [2] cb 60 [2] f4 7c }

  condition:
    any of them
}