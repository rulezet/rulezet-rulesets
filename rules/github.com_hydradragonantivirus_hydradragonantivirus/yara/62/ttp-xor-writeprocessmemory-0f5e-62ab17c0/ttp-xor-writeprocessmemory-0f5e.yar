rule TTP_XOR_WriteProcessMemory_0f5e {
  strings:
    $key_0f5e = { 58 2c [2] 6a 0e [2] 6c 3b [2] 42 3b [2] 7d 27 }

  condition:
    any of them
}