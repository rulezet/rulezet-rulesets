rule TTP_XOR_WriteProcessMemory_8119 {
  strings:
    $key_8119 = { d6 6b [2] e4 49 [2] e2 7c [2] cc 7c [2] f3 60 }

  condition:
    any of them
}