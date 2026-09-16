rule TTP_XOR_WriteProcessMemory_821b {
  strings:
    $key_821b = { d5 69 [2] e7 4b [2] e1 7e [2] cf 7e [2] f0 62 }

  condition:
    any of them
}