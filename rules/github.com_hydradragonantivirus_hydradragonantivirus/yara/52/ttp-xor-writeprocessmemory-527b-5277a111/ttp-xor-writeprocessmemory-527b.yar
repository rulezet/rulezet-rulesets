rule TTP_XOR_WriteProcessMemory_527b {
  strings:
    $key_527b = { 05 09 [2] 37 2b [2] 31 1e [2] 1f 1e [2] 20 02 }

  condition:
    any of them
}