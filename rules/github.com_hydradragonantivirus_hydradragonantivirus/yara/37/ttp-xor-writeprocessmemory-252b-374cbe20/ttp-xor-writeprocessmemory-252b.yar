rule TTP_XOR_WriteProcessMemory_252b {
  strings:
    $key_252b = { 72 59 [2] 40 7b [2] 46 4e [2] 68 4e [2] 57 52 }

  condition:
    any of them
}