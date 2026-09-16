rule TTP_XOR_WriteProcessMemory_1a6e {
  strings:
    $key_1a6e = { 4d 1c [2] 7f 3e [2] 79 0b [2] 57 0b [2] 68 17 }

  condition:
    any of them
}