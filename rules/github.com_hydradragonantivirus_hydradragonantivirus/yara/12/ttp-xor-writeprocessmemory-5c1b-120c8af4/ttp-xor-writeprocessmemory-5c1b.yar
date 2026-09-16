rule TTP_XOR_WriteProcessMemory_5c1b {
  strings:
    $key_5c1b = { 0b 69 [2] 39 4b [2] 3f 7e [2] 11 7e [2] 2e 62 }

  condition:
    any of them
}