rule TTP_XOR_WriteProcessMemory_7f98 {
  strings:
    $key_7f98 = { 28 ea [2] 1a c8 [2] 1c fd [2] 32 fd [2] 0d e1 }

  condition:
    any of them
}