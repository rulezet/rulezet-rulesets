rule TTP_XOR_WriteProcessMemory_6b98 {
  strings:
    $key_6b98 = { 3c ea [2] 0e c8 [2] 08 fd [2] 26 fd [2] 19 e1 }

  condition:
    any of them
}