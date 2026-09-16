rule TTP_XOR_WriteProcessMemory_823b {
  strings:
    $key_823b = { d5 49 [2] e7 6b [2] e1 5e [2] cf 5e [2] f0 42 }

  condition:
    any of them
}