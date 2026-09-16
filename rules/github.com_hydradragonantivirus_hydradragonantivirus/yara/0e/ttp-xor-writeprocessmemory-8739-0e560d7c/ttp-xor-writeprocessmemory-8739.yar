rule TTP_XOR_WriteProcessMemory_8739 {
  strings:
    $key_8739 = { d0 4b [2] e2 69 [2] e4 5c [2] ca 5c [2] f5 40 }

  condition:
    any of them
}