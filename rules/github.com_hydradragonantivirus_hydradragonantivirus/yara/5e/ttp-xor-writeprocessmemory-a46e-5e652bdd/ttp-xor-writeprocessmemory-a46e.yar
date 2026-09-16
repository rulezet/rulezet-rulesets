rule TTP_XOR_WriteProcessMemory_a46e {
  strings:
    $key_a46e = { f3 1c [2] c1 3e [2] c7 0b [2] e9 0b [2] d6 17 }

  condition:
    any of them
}