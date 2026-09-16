rule TTP_XOR_WriteProcessMemory_81e8 {
  strings:
    $key_81e8 = { d6 9a [2] e4 b8 [2] e2 8d [2] cc 8d [2] f3 91 }

  condition:
    any of them
}