rule TTP_XOR_WriteProcessMemory_686b {
  strings:
    $key_686b = { 3f 19 [2] 0d 3b [2] 0b 0e [2] 25 0e [2] 1a 12 }

  condition:
    any of them
}