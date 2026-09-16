rule TTP_XOR_WriteProcessMemory_845c {
  strings:
    $key_845c = { d3 2e [2] e1 0c [2] e7 39 [2] c9 39 [2] f6 25 }

  condition:
    any of them
}