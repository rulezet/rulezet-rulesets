rule TTP_XOR_WriteProcessMemory_830b {
  strings:
    $key_830b = { d4 79 [2] e6 5b [2] e0 6e [2] ce 6e [2] f1 72 }

  condition:
    any of them
}