rule TTP_XOR_WriteProcessMemory_b46b {
  strings:
    $key_b46b = { e3 19 [2] d1 3b [2] d7 0e [2] f9 0e [2] c6 12 }

  condition:
    any of them
}