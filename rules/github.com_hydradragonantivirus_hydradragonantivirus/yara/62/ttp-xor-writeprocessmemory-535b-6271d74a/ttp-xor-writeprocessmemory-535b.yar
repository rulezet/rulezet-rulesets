rule TTP_XOR_WriteProcessMemory_535b {
  strings:
    $key_535b = { 04 29 [2] 36 0b [2] 30 3e [2] 1e 3e [2] 21 22 }

  condition:
    any of them
}