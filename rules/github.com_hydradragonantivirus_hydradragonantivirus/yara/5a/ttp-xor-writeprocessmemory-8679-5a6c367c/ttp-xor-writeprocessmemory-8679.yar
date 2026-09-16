rule TTP_XOR_WriteProcessMemory_8679 {
  strings:
    $key_8679 = { d1 0b [2] e3 29 [2] e5 1c [2] cb 1c [2] f4 00 }

  condition:
    any of them
}