rule TTP_XOR_WriteProcessMemory_1c1b {
  strings:
    $key_1c1b = { 4b 69 [2] 79 4b [2] 7f 7e [2] 51 7e [2] 6e 62 }

  condition:
    any of them
}