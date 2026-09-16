rule TTP_XOR_WriteProcessMemory_410b {
  strings:
    $key_410b = { 16 79 [2] 24 5b [2] 22 6e [2] 0c 6e [2] 33 72 }

  condition:
    any of them
}