rule TTP_XOR_WriteProcessMemory_864e {
  strings:
    $key_864e = { d1 3c [2] e3 1e [2] e5 2b [2] cb 2b [2] f4 37 }

  condition:
    any of them
}