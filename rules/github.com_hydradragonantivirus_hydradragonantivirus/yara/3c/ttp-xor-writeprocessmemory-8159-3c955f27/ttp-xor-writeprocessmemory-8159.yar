rule TTP_XOR_WriteProcessMemory_8159 {
  strings:
    $key_8159 = { d6 2b [2] e4 09 [2] e2 3c [2] cc 3c [2] f3 20 }

  condition:
    any of them
}