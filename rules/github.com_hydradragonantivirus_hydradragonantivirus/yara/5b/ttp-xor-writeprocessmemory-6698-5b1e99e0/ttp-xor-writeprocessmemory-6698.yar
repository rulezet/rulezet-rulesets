rule TTP_XOR_WriteProcessMemory_6698 {
  strings:
    $key_6698 = { 31 ea [2] 03 c8 [2] 05 fd [2] 2b fd [2] 14 e1 }

  condition:
    any of them
}