rule TTP_XOR_WriteProcessMemory_337b {
  strings:
    $key_337b = { 64 09 [2] 56 2b [2] 50 1e [2] 7e 1e [2] 41 02 }

  condition:
    any of them
}