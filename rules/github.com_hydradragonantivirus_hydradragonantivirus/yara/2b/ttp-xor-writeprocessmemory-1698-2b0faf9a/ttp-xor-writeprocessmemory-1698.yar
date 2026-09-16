rule TTP_XOR_WriteProcessMemory_1698 {
  strings:
    $key_1698 = { 41 ea [2] 73 c8 [2] 75 fd [2] 5b fd [2] 64 e1 }

  condition:
    any of them
}