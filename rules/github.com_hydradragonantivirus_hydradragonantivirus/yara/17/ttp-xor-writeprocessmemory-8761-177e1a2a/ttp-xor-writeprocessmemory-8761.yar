rule TTP_XOR_WriteProcessMemory_8761 {
  strings:
    $key_8761 = { d0 13 [2] e2 31 [2] e4 04 [2] ca 04 [2] f5 18 }

  condition:
    any of them
}