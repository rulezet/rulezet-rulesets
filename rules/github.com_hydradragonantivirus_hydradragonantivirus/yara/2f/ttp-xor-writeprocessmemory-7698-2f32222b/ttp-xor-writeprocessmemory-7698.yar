rule TTP_XOR_WriteProcessMemory_7698 {
  strings:
    $key_7698 = { 21 ea [2] 13 c8 [2] 15 fd [2] 3b fd [2] 04 e1 }

  condition:
    any of them
}