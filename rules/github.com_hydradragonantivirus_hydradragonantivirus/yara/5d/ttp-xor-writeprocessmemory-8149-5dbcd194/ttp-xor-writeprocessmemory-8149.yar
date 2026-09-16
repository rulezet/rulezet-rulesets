rule TTP_XOR_WriteProcessMemory_8149 {
  strings:
    $key_8149 = { d6 3b [2] e4 19 [2] e2 2c [2] cc 2c [2] f3 30 }

  condition:
    any of them
}