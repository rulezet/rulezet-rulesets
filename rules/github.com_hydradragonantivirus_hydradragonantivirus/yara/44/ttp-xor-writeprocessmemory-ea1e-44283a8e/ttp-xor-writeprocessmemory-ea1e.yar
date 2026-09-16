rule TTP_XOR_WriteProcessMemory_ea1e {
  strings:
    $key_ea1e = { bd 6c [2] 8f 4e [2] 89 7b [2] a7 7b [2] 98 67 }

  condition:
    any of them
}