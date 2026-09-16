rule TTP_XOR_WriteProcessMemory_ea2b {
  strings:
    $key_ea2b = { bd 59 [2] 8f 7b [2] 89 4e [2] a7 4e [2] 98 52 }

  condition:
    any of them
}