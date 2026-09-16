rule TTP_XOR_WriteProcessMemory_827c {
  strings:
    $key_827c = { d5 0e [2] e7 2c [2] e1 19 [2] cf 19 [2] f0 05 }

  condition:
    any of them
}