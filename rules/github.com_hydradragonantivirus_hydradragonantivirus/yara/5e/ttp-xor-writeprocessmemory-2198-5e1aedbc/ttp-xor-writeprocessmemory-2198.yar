rule TTP_XOR_WriteProcessMemory_2198 {
  strings:
    $key_2198 = { 76 ea [2] 44 c8 [2] 42 fd [2] 6c fd [2] 53 e1 }

  condition:
    any of them
}