rule TTP_XOR_WriteProcessMemory_956c {
  strings:
    $key_956c = { c2 1e [2] f0 3c [2] f6 09 [2] d8 09 [2] e7 15 }

  condition:
    any of them
}