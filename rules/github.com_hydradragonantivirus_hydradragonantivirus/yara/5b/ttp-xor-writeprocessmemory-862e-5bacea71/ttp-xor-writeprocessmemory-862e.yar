rule TTP_XOR_WriteProcessMemory_862e {
  strings:
    $key_862e = { d1 5c [2] e3 7e [2] e5 4b [2] cb 4b [2] f4 57 }

  condition:
    any of them
}