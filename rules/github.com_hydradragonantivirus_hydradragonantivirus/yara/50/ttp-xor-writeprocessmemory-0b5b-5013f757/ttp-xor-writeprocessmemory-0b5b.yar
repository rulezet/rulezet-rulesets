rule TTP_XOR_WriteProcessMemory_0b5b {
  strings:
    $key_0b5b = { 5c 29 [2] 6e 0b [2] 68 3e [2] 46 3e [2] 79 22 }

  condition:
    any of them
}