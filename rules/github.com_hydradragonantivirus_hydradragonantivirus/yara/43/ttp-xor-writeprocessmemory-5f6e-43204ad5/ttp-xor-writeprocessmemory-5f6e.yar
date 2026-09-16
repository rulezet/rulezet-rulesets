rule TTP_XOR_WriteProcessMemory_5f6e {
  strings:
    $key_5f6e = { 08 1c [2] 3a 3e [2] 3c 0b [2] 12 0b [2] 2d 17 }

  condition:
    any of them
}