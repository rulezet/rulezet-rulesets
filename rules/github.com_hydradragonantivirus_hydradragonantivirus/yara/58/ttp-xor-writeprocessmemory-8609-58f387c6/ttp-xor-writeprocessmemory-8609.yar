rule TTP_XOR_WriteProcessMemory_8609 {
  strings:
    $key_8609 = { d1 7b [2] e3 59 [2] e5 6c [2] cb 6c [2] f4 70 }

  condition:
    any of them
}