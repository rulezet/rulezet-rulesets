rule TTP_XOR_WriteProcessMemory_a06e {
  strings:
    $key_a06e = { f7 1c [2] c5 3e [2] c3 0b [2] ed 0b [2] d2 17 }

  condition:
    any of them
}