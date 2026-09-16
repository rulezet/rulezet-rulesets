rule TTP_XOR_WriteProcessMemory_555b {
  strings:
    $key_555b = { 02 29 [2] 30 0b [2] 36 3e [2] 18 3e [2] 27 22 }

  condition:
    any of them
}