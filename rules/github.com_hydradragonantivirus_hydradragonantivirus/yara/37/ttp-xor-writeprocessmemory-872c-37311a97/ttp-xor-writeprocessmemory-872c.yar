rule TTP_XOR_WriteProcessMemory_872c {
  strings:
    $key_872c = { d0 5e [2] e2 7c [2] e4 49 [2] ca 49 [2] f5 55 }

  condition:
    any of them
}