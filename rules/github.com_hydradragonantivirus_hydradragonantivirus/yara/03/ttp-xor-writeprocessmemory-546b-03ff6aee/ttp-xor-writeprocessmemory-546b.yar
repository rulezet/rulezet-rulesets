rule TTP_XOR_WriteProcessMemory_546b {
  strings:
    $key_546b = { 03 19 [2] 31 3b [2] 37 0e [2] 19 0e [2] 26 12 }

  condition:
    any of them
}