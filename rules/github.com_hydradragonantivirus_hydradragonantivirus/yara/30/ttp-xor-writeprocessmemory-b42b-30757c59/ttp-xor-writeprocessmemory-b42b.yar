rule TTP_XOR_WriteProcessMemory_b42b {
  strings:
    $key_b42b = { e3 59 [2] d1 7b [2] d7 4e [2] f9 4e [2] c6 52 }

  condition:
    any of them
}