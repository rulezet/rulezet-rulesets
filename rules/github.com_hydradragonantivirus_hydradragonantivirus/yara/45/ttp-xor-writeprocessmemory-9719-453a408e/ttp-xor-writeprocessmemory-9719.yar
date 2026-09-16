rule TTP_XOR_WriteProcessMemory_9719 {
  strings:
    $key_9719 = { c0 6b [2] f2 49 [2] f4 7c [2] da 7c [2] e5 60 }

  condition:
    any of them
}