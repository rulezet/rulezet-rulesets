rule TTP_XOR_WriteProcessMemory_823e {
  strings:
    $key_823e = { d5 4c [2] e7 6e [2] e1 5b [2] cf 5b [2] f0 47 }

  condition:
    any of them
}