rule TTP_XOR_WriteProcessMemory_463e {
  strings:
    $key_463e = { 11 4c [2] 23 6e [2] 25 5b [2] 0b 5b [2] 34 47 }

  condition:
    any of them
}