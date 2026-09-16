rule TTP_XOR_WriteProcessMemory_b53e {
  strings:
    $key_b53e = { e2 4c [2] d0 6e [2] d6 5b [2] f8 5b [2] c7 47 }

  condition:
    any of them
}