rule TTP_XOR_WriteProcessMemory_170b {
  strings:
    $key_170b = { 40 79 [2] 72 5b [2] 74 6e [2] 5a 6e [2] 65 72 }

  condition:
    any of them
}