rule TTP_XOR_WriteProcessMemory_467b {
  strings:
    $key_467b = { 11 09 [2] 23 2b [2] 25 1e [2] 0b 1e [2] 34 02 }

  condition:
    any of them
}