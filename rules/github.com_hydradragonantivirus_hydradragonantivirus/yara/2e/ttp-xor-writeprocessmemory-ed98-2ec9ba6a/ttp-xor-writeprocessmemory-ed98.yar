rule TTP_XOR_WriteProcessMemory_ed98 {
  strings:
    $key_ed98 = { ba ea [2] 88 c8 [2] 8e fd [2] a0 fd [2] 9f e1 }

  condition:
    any of them
}