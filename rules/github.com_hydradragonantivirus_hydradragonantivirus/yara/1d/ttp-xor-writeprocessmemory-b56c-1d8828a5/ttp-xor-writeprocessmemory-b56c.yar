rule TTP_XOR_WriteProcessMemory_b56c {
  strings:
    $key_b56c = { e2 1e [2] d0 3c [2] d6 09 [2] f8 09 [2] c7 15 }

  condition:
    any of them
}