rule TTP_XOR_WriteProcessMemory_1f98 {
  strings:
    $key_1f98 = { 48 ea [2] 7a c8 [2] 7c fd [2] 52 fd [2] 6d e1 }

  condition:
    any of them
}