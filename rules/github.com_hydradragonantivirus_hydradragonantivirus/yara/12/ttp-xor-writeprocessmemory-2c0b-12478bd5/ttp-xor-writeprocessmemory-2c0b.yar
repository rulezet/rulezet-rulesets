rule TTP_XOR_WriteProcessMemory_2c0b {
  strings:
    $key_2c0b = { 7b 79 [2] 49 5b [2] 4f 6e [2] 61 6e [2] 5e 72 }

  condition:
    any of them
}