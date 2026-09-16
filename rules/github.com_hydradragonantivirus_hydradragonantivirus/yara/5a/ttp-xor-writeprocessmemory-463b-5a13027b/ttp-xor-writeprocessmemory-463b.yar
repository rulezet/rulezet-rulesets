rule TTP_XOR_WriteProcessMemory_463b {
  strings:
    $key_463b = { 11 49 [2] 23 6b [2] 25 5e [2] 0b 5e [2] 34 42 }

  condition:
    any of them
}