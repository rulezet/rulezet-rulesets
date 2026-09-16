rule TTP_XOR_WriteProcessMemory_836e {
  strings:
    $key_836e = { d4 1c [2] e6 3e [2] e0 0b [2] ce 0b [2] f1 17 }

  condition:
    any of them
}