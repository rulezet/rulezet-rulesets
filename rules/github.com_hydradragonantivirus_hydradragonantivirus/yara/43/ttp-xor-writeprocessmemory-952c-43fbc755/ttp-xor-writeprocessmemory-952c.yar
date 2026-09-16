rule TTP_XOR_WriteProcessMemory_952c {
  strings:
    $key_952c = { c2 5e [2] f0 7c [2] f6 49 [2] d8 49 [2] e7 55 }

  condition:
    any of them
}