rule TTP_XOR_WriteProcessMemory_804e {
  strings:
    $key_804e = { d7 3c [2] e5 1e [2] e3 2b [2] cd 2b [2] f2 37 }

  condition:
    any of them
}