rule TTP_XOR_WriteProcessMemory_1e98 {
  strings:
    $key_1e98 = { 49 ea [2] 7b c8 [2] 7d fd [2] 53 fd [2] 6c e1 }

  condition:
    any of them
}