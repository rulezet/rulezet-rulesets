rule TTP_XOR_WriteProcessMemory_652e {
  strings:
    $key_652e = { 32 5c [2] 00 7e [2] 06 4b [2] 28 4b [2] 17 57 }

  condition:
    any of them
}