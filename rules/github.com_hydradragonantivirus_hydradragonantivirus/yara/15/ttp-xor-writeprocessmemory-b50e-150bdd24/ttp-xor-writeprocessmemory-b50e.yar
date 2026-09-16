rule TTP_XOR_WriteProcessMemory_b50e {
  strings:
    $key_b50e = { e2 7c [2] d0 5e [2] d6 6b [2] f8 6b [2] c7 77 }

  condition:
    any of them
}