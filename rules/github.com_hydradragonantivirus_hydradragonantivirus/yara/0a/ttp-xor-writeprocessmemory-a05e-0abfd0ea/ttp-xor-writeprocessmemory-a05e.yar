rule TTP_XOR_WriteProcessMemory_a05e {
  strings:
    $key_a05e = { f7 2c [2] c5 0e [2] c3 3b [2] ed 3b [2] d2 27 }

  condition:
    any of them
}