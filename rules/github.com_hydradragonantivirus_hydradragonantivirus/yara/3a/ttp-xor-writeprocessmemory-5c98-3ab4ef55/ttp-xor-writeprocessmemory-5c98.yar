rule TTP_XOR_WriteProcessMemory_5c98 {
  strings:
    $key_5c98 = { 0b ea [2] 39 c8 [2] 3f fd [2] 11 fd [2] 2e e1 }

  condition:
    any of them
}