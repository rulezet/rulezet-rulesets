rule TTP_XOR_WriteProcessMemory_872d {
  strings:
    $key_872d = { d0 5f [2] e2 7d [2] e4 48 [2] ca 48 [2] f5 54 }

  condition:
    any of them
}