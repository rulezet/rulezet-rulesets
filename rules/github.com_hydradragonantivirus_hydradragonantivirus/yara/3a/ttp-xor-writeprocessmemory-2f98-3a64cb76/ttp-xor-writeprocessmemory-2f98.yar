rule TTP_XOR_WriteProcessMemory_2f98 {
  strings:
    $key_2f98 = { 78 ea [2] 4a c8 [2] 4c fd [2] 62 fd [2] 5d e1 }

  condition:
    any of them
}