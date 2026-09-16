rule TTP_XOR_WriteProcessMemory_825c {
  strings:
    $key_825c = { d5 2e [2] e7 0c [2] e1 39 [2] cf 39 [2] f0 25 }

  condition:
    any of them
}