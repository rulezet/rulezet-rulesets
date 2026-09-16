rule TTP_XOR_WriteProcessMemory_b41b {
  strings:
    $key_b41b = { e3 69 [2] d1 4b [2] d7 7e [2] f9 7e [2] c6 62 }

  condition:
    any of them
}