rule TTP_XOR_WriteProcessMemory_737b {
  strings:
    $key_737b = { 24 09 [2] 16 2b [2] 10 1e [2] 3e 1e [2] 01 02 }

  condition:
    any of them
}