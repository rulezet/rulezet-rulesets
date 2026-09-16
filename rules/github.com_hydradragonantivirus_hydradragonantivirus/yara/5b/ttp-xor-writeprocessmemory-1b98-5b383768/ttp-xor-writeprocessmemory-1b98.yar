rule TTP_XOR_WriteProcessMemory_1b98 {
  strings:
    $key_1b98 = { 4c ea [2] 7e c8 [2] 78 fd [2] 56 fd [2] 69 e1 }

  condition:
    any of them
}