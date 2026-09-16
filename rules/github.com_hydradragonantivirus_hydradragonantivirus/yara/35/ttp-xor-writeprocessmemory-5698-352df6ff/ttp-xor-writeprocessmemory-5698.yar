rule TTP_XOR_WriteProcessMemory_5698 {
  strings:
    $key_5698 = { 01 ea [2] 33 c8 [2] 35 fd [2] 1b fd [2] 24 e1 }

  condition:
    any of them
}