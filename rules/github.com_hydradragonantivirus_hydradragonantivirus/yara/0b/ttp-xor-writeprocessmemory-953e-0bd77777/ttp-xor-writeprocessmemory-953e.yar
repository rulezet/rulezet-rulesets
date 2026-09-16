rule TTP_XOR_WriteProcessMemory_953e {
  strings:
    $key_953e = { c2 4c [2] f0 6e [2] f6 5b [2] d8 5b [2] e7 47 }

  condition:
    any of them
}