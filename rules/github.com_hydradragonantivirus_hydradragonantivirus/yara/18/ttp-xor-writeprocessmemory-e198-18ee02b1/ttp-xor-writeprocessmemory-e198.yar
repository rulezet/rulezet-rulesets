rule TTP_XOR_WriteProcessMemory_e198 {
  strings:
    $key_e198 = { b6 ea [2] 84 c8 [2] 82 fd [2] ac fd [2] 93 e1 }

  condition:
    any of them
}