rule TTP_XOR_WriteProcessMemory_7c98 {
  strings:
    $key_7c98 = { 2b ea [2] 19 c8 [2] 1f fd [2] 31 fd [2] 0e e1 }

  condition:
    any of them
}