rule TTP_XOR_WriteProcessMemory_b11e {
  strings:
    $key_b11e = { e6 6c [2] d4 4e [2] d2 7b [2] fc 7b [2] c3 67 }

  condition:
    any of them
}