rule TTP_XOR_WriteProcessMemory_8629 {
  strings:
    $key_8629 = { d1 5b [2] e3 79 [2] e5 4c [2] cb 4c [2] f4 50 }

  condition:
    any of them
}