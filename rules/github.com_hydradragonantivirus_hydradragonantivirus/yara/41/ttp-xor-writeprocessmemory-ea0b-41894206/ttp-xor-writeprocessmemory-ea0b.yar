rule TTP_XOR_WriteProcessMemory_ea0b {
  strings:
    $key_ea0b = { bd 79 [2] 8f 5b [2] 89 6e [2] a7 6e [2] 98 72 }

  condition:
    any of them
}