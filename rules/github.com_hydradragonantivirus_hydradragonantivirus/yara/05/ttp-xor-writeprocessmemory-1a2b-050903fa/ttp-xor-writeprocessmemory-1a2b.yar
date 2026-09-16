rule TTP_XOR_WriteProcessMemory_1a2b {
  strings:
    $key_1a2b = { 4d 59 [2] 7f 7b [2] 79 4e [2] 57 4e [2] 68 52 }

  condition:
    any of them
}