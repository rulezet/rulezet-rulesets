rule TTP_XOR_WriteProcessMemory_2c98 {
  strings:
    $key_2c98 = { 7b ea [2] 49 c8 [2] 4f fd [2] 61 fd [2] 5e e1 }

  condition:
    any of them
}