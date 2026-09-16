rule TTP_XOR_WriteProcessMemory_0198 {
  strings:
    $key_0198 = { 56 ea [2] 64 c8 [2] 62 fd [2] 4c fd [2] 73 e1 }

  condition:
    any of them
}