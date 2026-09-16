rule TTP_XOR_WriteProcessMemory_934c {
  strings:
    $key_934c = { c4 3e [2] f6 1c [2] f0 29 [2] de 29 [2] e1 35 }

  condition:
    any of them
}