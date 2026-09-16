rule TTP_XOR_WriteProcessMemory_745b {
  strings:
    $key_745b = { 23 29 [2] 11 0b [2] 17 3e [2] 39 3e [2] 06 22 }

  condition:
    any of them
}