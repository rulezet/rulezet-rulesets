rule TTP_XOR_WriteProcessMemory_652d {
  strings:
    $key_652d = { 32 5f [2] 00 7d [2] 06 48 [2] 28 48 [2] 17 54 }

  condition:
    any of them
}