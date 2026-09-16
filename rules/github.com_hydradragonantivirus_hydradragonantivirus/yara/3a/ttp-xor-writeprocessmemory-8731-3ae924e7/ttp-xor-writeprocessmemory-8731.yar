rule TTP_XOR_WriteProcessMemory_8731 {
  strings:
    $key_8731 = { d0 43 [2] e2 61 [2] e4 54 [2] ca 54 [2] f5 48 }

  condition:
    any of them
}