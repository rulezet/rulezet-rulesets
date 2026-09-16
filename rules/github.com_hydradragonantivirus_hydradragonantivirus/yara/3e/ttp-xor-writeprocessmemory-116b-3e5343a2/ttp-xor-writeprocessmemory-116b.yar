rule TTP_XOR_WriteProcessMemory_116b {
  strings:
    $key_116b = { 46 19 [2] 74 3b [2] 72 0e [2] 5c 0e [2] 63 12 }

  condition:
    any of them
}