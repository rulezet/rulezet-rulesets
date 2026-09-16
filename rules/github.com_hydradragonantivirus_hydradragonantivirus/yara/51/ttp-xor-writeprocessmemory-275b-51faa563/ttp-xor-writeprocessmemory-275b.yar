rule TTP_XOR_WriteProcessMemory_275b {
  strings:
    $key_275b = { 70 29 [2] 42 0b [2] 44 3e [2] 6a 3e [2] 55 22 }

  condition:
    any of them
}