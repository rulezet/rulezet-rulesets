rule TTP_XOR_WriteProcessMemory_841c {
  strings:
    $key_841c = { d3 6e [2] e1 4c [2] e7 79 [2] c9 79 [2] f6 65 }

  condition:
    any of them
}