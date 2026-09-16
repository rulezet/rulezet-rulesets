rule TTP_XOR_WriteProcessMemory_7b98 {
  strings:
    $key_7b98 = { 2c ea [2] 1e c8 [2] 18 fd [2] 36 fd [2] 09 e1 }

  condition:
    any of them
}