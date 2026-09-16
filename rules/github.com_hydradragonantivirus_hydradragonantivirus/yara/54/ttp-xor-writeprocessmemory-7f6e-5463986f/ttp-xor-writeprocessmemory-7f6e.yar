rule TTP_XOR_WriteProcessMemory_7f6e {
  strings:
    $key_7f6e = { 28 1c [2] 1a 3e [2] 1c 0b [2] 32 0b [2] 0d 17 }

  condition:
    any of them
}