rule TTP_XOR_WriteProcessMemory_81fc {
  strings:
    $key_81fc = { d6 8e [2] e4 ac [2] e2 99 [2] cc 99 [2] f3 85 }

  condition:
    any of them
}