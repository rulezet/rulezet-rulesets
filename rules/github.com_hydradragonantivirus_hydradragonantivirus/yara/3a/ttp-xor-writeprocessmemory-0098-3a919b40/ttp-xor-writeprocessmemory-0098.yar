rule TTP_XOR_WriteProcessMemory_0098 {
  strings:
    $key_0098 = { 57 ea [2] 65 c8 [2] 63 fd [2] 4d fd [2] 72 e1 }

  condition:
    any of them
}