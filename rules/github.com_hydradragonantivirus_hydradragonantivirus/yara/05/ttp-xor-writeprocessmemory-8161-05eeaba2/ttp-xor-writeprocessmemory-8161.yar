rule TTP_XOR_WriteProcessMemory_8161 {
  strings:
    $key_8161 = { d6 13 [2] e4 31 [2] e2 04 [2] cc 04 [2] f3 18 }

  condition:
    any of them
}