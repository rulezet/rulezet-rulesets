rule TTP_XOR_WriteProcessMemory_1c0b {
  strings:
    $key_1c0b = { 4b 79 [2] 79 5b [2] 7f 6e [2] 51 6e [2] 6e 72 }

  condition:
    any of them
}