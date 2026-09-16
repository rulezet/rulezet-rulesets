rule TTP_XOR_WriteProcessMemory_745e {
  strings:
    $key_745e = { 23 2c [2] 11 0e [2] 17 3b [2] 39 3b [2] 06 27 }

  condition:
    any of them
}