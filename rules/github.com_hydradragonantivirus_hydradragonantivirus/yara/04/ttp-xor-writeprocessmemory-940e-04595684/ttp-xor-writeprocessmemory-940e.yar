rule TTP_XOR_WriteProcessMemory_940e {
  strings:
    $key_940e = { c3 7c [2] f1 5e [2] f7 6b [2] d9 6b [2] e6 77 }

  condition:
    any of them
}