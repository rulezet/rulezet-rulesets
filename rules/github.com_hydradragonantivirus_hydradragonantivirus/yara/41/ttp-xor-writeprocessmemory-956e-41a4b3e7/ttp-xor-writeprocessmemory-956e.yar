rule TTP_XOR_WriteProcessMemory_956e {
  strings:
    $key_956e = { c2 1c [2] f0 3e [2] f6 0b [2] d8 0b [2] e7 17 }

  condition:
    any of them
}