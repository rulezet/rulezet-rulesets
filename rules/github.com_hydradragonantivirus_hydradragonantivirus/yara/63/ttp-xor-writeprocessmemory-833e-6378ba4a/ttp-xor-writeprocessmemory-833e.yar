rule TTP_XOR_WriteProcessMemory_833e {
  strings:
    $key_833e = { d4 4c [2] e6 6e [2] e0 5b [2] ce 5b [2] f1 47 }

  condition:
    any of them
}