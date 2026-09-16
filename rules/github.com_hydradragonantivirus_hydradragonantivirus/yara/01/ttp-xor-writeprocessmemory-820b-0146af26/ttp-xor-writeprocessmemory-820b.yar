rule TTP_XOR_WriteProcessMemory_820b {
  strings:
    $key_820b = { d5 79 [2] e7 5b [2] e1 6e [2] cf 6e [2] f0 72 }

  condition:
    any of them
}