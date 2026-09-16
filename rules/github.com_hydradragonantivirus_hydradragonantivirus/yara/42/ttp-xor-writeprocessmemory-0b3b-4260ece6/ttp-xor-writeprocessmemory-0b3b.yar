rule TTP_XOR_WriteProcessMemory_0b3b {
  strings:
    $key_0b3b = { 5c 49 [2] 6e 6b [2] 68 5e [2] 46 5e [2] 79 42 }

  condition:
    any of them
}