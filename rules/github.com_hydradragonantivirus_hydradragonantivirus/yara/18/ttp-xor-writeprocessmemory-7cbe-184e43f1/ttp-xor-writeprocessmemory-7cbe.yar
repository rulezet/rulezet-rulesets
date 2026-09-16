rule TTP_XOR_WriteProcessMemory_7cbe {
  strings:
    $key_7cbe = { 2b cc [2] 19 ee [2] 1f db [2] 31 db [2] 0e c7 }

  condition:
    any of them
}