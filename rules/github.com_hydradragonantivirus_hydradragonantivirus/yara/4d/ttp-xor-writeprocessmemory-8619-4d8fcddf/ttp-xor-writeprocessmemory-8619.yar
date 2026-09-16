rule TTP_XOR_WriteProcessMemory_8619 {
  strings:
    $key_8619 = { d1 6b [2] e3 49 [2] e5 7c [2] cb 7c [2] f4 60 }

  condition:
    any of them
}