rule TTP_XOR_WriteProcessMemory_757b {
  strings:
    $key_757b = { 22 09 [2] 10 2b [2] 16 1e [2] 38 1e [2] 07 02 }

  condition:
    any of them
}