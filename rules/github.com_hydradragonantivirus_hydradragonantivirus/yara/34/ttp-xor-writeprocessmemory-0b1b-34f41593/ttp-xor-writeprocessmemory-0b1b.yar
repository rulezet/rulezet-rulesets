rule TTP_XOR_WriteProcessMemory_0b1b {
  strings:
    $key_0b1b = { 5c 69 [2] 6e 4b [2] 68 7e [2] 46 7e [2] 79 62 }

  condition:
    any of them
}