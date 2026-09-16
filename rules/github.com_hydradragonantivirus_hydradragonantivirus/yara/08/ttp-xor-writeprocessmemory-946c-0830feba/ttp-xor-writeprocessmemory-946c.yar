rule TTP_XOR_WriteProcessMemory_946c {
  strings:
    $key_946c = { c3 1e [2] f1 3c [2] f7 09 [2] d9 09 [2] e6 15 }

  condition:
    any of them
}