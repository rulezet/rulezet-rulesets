rule TTP_XOR_WriteProcessMemory_ea3b {
  strings:
    $key_ea3b = { bd 49 [2] 8f 6b [2] 89 5e [2] a7 5e [2] 98 42 }

  condition:
    any of them
}