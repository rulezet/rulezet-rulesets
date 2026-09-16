rule TTP_XOR_WriteProcessMemory_955c {
  strings:
    $key_955c = { c2 2e [2] f0 0c [2] f6 39 [2] d8 39 [2] e7 25 }

  condition:
    any of them
}