rule TTP_XOR_WriteProcessMemory_952b {
  strings:
    $key_952b = { c2 59 [2] f0 7b [2] f6 4e [2] d8 4e [2] e7 52 }

  condition:
    any of them
}