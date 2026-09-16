rule TTP_XOR_WriteProcessMemory_1a1b {
  strings:
    $key_1a1b = { 4d 69 [2] 7f 4b [2] 79 7e [2] 57 7e [2] 68 62 }

  condition:
    any of them
}