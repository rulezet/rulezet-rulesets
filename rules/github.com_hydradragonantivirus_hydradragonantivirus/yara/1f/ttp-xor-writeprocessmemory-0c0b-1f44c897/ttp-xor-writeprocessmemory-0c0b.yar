rule TTP_XOR_WriteProcessMemory_0c0b {
  strings:
    $key_0c0b = { 5b 79 [2] 69 5b [2] 6f 6e [2] 41 6e [2] 7e 72 }

  condition:
    any of them
}