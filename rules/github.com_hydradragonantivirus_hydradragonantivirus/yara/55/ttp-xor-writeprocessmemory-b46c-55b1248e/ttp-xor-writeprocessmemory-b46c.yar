rule TTP_XOR_WriteProcessMemory_b46c {
  strings:
    $key_b46c = { e3 1e [2] d1 3c [2] d7 09 [2] f9 09 [2] c6 15 }

  condition:
    any of them
}