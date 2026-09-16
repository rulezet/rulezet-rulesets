rule TTP_XOR_WriteProcessMemory_656e {
  strings:
    $key_656e = { 32 1c [2] 00 3e [2] 06 0b [2] 28 0b [2] 17 17 }

  condition:
    any of them
}