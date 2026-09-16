rule TTP_XOR_WriteProcessMemory_520b {
  strings:
    $key_520b = { 05 79 [2] 37 5b [2] 31 6e [2] 1f 6e [2] 20 72 }

  condition:
    any of them
}