rule TTP_XOR_WriteProcessMemory_137b {
  strings:
    $key_137b = { 44 09 [2] 76 2b [2] 70 1e [2] 5e 1e [2] 61 02 }

  condition:
    any of them
}