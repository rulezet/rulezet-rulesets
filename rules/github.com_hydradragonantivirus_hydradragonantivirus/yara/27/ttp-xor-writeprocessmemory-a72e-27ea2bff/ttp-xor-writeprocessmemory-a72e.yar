rule TTP_XOR_WriteProcessMemory_a72e {
  strings:
    $key_a72e = { f0 5c [2] c2 7e [2] c4 4b [2] ea 4b [2] d5 57 }

  condition:
    any of them
}