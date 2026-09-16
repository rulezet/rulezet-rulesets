rule TTP_XOR_WriteProcessMemory_4b7b {
  strings:
    $key_4b7b = { 1c 09 [2] 2e 2b [2] 28 1e [2] 06 1e [2] 39 02 }

  condition:
    any of them
}