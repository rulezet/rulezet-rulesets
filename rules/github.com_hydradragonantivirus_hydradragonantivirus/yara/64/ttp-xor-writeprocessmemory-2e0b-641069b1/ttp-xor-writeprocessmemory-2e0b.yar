rule TTP_XOR_WriteProcessMemory_2e0b {
  strings:
    $key_2e0b = { 79 79 [2] 4b 5b [2] 4d 6e [2] 63 6e [2] 5c 72 }

  condition:
    any of them
}