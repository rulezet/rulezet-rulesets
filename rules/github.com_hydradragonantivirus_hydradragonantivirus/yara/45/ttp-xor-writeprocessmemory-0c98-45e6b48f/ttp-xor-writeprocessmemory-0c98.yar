rule TTP_XOR_WriteProcessMemory_0c98 {
  strings:
    $key_0c98 = { 5b ea [2] 69 c8 [2] 6f fd [2] 41 fd [2] 7e e1 }

  condition:
    any of them
}