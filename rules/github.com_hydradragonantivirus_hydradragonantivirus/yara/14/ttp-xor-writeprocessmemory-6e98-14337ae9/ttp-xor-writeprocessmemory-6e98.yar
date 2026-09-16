rule TTP_XOR_WriteProcessMemory_6e98 {
  strings:
    $key_6e98 = { 39 ea [2] 0b c8 [2] 0d fd [2] 23 fd [2] 1c e1 }

  condition:
    any of them
}