rule TTP_XOR_WriteProcessMemory_8709 {
  strings:
    $key_8709 = { d0 7b [2] e2 59 [2] e4 6c [2] ca 6c [2] f5 70 }

  condition:
    any of them
}