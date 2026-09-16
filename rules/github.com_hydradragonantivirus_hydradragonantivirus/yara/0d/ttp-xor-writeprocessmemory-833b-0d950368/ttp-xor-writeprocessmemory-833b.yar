rule TTP_XOR_WriteProcessMemory_833b {
  strings:
    $key_833b = { d4 49 [2] e6 6b [2] e0 5e [2] ce 5e [2] f1 42 }

  condition:
    any of them
}