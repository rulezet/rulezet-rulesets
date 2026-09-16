rule TTP_XOR_WriteProcessMemory_457b {
  strings:
    $key_457b = { 12 09 [2] 20 2b [2] 26 1e [2] 08 1e [2] 37 02 }

  condition:
    any of them
}