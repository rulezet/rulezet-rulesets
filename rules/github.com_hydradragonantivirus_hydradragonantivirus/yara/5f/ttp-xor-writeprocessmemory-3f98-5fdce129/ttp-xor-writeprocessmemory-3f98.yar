rule TTP_XOR_WriteProcessMemory_3f98 {
  strings:
    $key_3f98 = { 68 ea [2] 5a c8 [2] 5c fd [2] 72 fd [2] 4d e1 }

  condition:
    any of them
}