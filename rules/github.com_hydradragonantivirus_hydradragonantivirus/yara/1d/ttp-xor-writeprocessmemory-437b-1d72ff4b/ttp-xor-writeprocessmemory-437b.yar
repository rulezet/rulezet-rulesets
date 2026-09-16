rule TTP_XOR_WriteProcessMemory_437b {
  strings:
    $key_437b = { 14 09 [2] 26 2b [2] 20 1e [2] 0e 1e [2] 31 02 }

  condition:
    any of them
}