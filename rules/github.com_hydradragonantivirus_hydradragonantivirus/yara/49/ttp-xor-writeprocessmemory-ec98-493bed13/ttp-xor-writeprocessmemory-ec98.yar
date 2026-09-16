rule TTP_XOR_WriteProcessMemory_ec98 {
  strings:
    $key_ec98 = { bb ea [2] 89 c8 [2] 8f fd [2] a1 fd [2] 9e e1 }

  condition:
    any of them
}