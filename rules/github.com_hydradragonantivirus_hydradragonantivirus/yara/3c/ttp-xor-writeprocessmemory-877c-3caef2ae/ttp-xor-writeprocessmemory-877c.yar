rule TTP_XOR_WriteProcessMemory_877c {
  strings:
    $key_877c = { d0 0e [2] e2 2c [2] e4 19 [2] ca 19 [2] f5 05 }

  condition:
    any of them
}