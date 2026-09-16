rule TTP_XOR_WriteProcessMemory_a52e {
  strings:
    $key_a52e = { f2 5c [2] c0 7e [2] c6 4b [2] e8 4b [2] d7 57 }

  condition:
    any of them
}