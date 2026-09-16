rule TTP_XOR_WriteProcessMemory_6198 {
  strings:
    $key_6198 = { 36 ea [2] 04 c8 [2] 02 fd [2] 2c fd [2] 13 e1 }

  condition:
    any of them
}