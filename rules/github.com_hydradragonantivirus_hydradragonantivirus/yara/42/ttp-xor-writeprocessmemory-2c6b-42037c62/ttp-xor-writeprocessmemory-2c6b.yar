rule TTP_XOR_WriteProcessMemory_2c6b {
  strings:
    $key_2c6b = { 7b 19 [2] 49 3b [2] 4f 0e [2] 61 0e [2] 5e 12 }

  condition:
    any of them
}