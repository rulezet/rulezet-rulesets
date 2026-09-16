rule TTP_XOR_WriteProcessMemory_2c5b {
  strings:
    $key_2c5b = { 7b 29 [2] 49 0b [2] 4f 3e [2] 61 3e [2] 5e 22 }

  condition:
    any of them
}