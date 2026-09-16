rule TTP_XOR_WriteProcessMemory_7d7b {
  strings:
    $key_7d7b = { 2a 09 [2] 18 2b [2] 1e 1e [2] 30 1e [2] 0f 02 }

  condition:
    any of them
}