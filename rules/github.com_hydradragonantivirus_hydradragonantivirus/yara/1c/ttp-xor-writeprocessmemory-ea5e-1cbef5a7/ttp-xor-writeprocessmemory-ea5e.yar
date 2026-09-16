rule TTP_XOR_WriteProcessMemory_ea5e {
  strings:
    $key_ea5e = { bd 2c [2] 8f 0e [2] 89 3b [2] a7 3b [2] 98 27 }

  condition:
    any of them
}