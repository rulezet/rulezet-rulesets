rule TTP_XOR_WriteProcessMemory_a56e {
  strings:
    $key_a56e = { f2 1c [2] c0 3e [2] c6 0b [2] e8 0b [2] d7 17 }

  condition:
    any of them
}