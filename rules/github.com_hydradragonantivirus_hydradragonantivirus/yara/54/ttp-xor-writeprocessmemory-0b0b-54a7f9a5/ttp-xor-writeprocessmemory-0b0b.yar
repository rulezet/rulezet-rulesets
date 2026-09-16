rule TTP_XOR_WriteProcessMemory_0b0b {
  strings:
    $key_0b0b = { 5c 79 [2] 6e 5b [2] 68 6e [2] 46 6e [2] 79 72 }

  condition:
    any of them
}