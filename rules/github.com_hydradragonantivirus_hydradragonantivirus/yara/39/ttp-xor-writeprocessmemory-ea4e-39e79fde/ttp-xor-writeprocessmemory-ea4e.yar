rule TTP_XOR_WriteProcessMemory_ea4e {
  strings:
    $key_ea4e = { bd 3c [2] 8f 1e [2] 89 2b [2] a7 2b [2] 98 37 }

  condition:
    any of them
}