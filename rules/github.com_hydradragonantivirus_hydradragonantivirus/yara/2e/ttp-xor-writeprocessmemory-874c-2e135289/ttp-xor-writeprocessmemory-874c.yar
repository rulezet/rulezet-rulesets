rule TTP_XOR_WriteProcessMemory_874c {
  strings:
    $key_874c = { d0 3e [2] e2 1c [2] e4 29 [2] ca 29 [2] f5 35 }

  condition:
    any of them
}