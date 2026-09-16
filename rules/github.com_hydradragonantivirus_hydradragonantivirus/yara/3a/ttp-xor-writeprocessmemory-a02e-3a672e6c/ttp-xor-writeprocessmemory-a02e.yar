rule TTP_XOR_WriteProcessMemory_a02e {
  strings:
    $key_a02e = { f7 5c [2] c5 7e [2] c3 4b [2] ed 4b [2] d2 57 }

  condition:
    any of them
}