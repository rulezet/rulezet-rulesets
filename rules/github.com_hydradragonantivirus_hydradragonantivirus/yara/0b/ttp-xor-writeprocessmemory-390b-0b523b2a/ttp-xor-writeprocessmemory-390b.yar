rule TTP_XOR_WriteProcessMemory_390b {
  strings:
    $key_390b = { 6e 79 [2] 5c 5b [2] 5a 6e [2] 74 6e [2] 4b 72 }

  condition:
    any of them
}