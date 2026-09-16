rule TTP_XOR_WriteProcessMemory_797b {
  strings:
    $key_797b = { 2e 09 [2] 1c 2b [2] 1a 1e [2] 34 1e [2] 0b 02 }

  condition:
    any of them
}