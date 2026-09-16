rule TTP_XOR_WriteProcessMemory_8719 {
  strings:
    $key_8719 = { d0 6b [2] e2 49 [2] e4 7c [2] ca 7c [2] f5 60 }

  condition:
    any of them
}