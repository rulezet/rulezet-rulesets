rule TTP_XOR_WriteProcessMemory_831b {
  strings:
    $key_831b = { d4 69 [2] e6 4b [2] e0 7e [2] ce 7e [2] f1 62 }

  condition:
    any of them
}