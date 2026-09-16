rule TTP_XOR_WriteProcessMemory_ea4b {
  strings:
    $key_ea4b = { bd 39 [2] 8f 1b [2] 89 2e [2] a7 2e [2] 98 32 }

  condition:
    any of them
}