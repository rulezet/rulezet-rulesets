rule TTP_XOR_WriteProcessMemory_b41c {
  strings:
    $key_b41c = { e3 6e [2] d1 4c [2] d7 79 [2] f9 79 [2] c6 65 }

  condition:
    any of them
}