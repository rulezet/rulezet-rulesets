rule TTP_XOR_WriteProcessMemory_652b {
  strings:
    $key_652b = { 32 59 [2] 00 7b [2] 06 4e [2] 28 4e [2] 17 52 }

  condition:
    any of them
}