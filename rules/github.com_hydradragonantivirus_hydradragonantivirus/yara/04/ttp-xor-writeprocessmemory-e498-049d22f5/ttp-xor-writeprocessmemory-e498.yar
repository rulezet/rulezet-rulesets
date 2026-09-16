rule TTP_XOR_WriteProcessMemory_e498 {
  strings:
    $key_e498 = { b3 ea [2] 81 c8 [2] 87 fd [2] a9 fd [2] 96 e1 }

  condition:
    any of them
}