rule TTP_XOR_WriteProcessMemory_4c98 {
  strings:
    $key_4c98 = { 1b ea [2] 29 c8 [2] 2f fd [2] 01 fd [2] 3e e1 }

  condition:
    any of them
}