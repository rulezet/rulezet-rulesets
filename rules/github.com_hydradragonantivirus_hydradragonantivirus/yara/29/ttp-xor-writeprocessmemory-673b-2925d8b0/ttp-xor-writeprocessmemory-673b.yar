rule TTP_XOR_WriteProcessMemory_673b {
  strings:
    $key_673b = { 30 49 [2] 02 6b [2] 04 5e [2] 2a 5e [2] 15 42 }

  condition:
    any of them
}