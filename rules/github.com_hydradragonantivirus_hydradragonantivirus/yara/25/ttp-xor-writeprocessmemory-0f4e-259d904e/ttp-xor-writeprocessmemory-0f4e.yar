rule TTP_XOR_WriteProcessMemory_0f4e {
  strings:
    $key_0f4e = { 58 3c [2] 6a 1e [2] 6c 2b [2] 42 2b [2] 7d 37 }

  condition:
    any of them
}