rule TTP_XOR_WriteProcessMemory_467e {
  strings:
    $key_467e = { 11 0c [2] 23 2e [2] 25 1b [2] 0b 1b [2] 34 07 }

  condition:
    any of them
}