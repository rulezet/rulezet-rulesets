rule TTP_XOR_WriteProcessMemory_e398 {
  strings:
    $key_e398 = { b4 ea [2] 86 c8 [2] 80 fd [2] ae fd [2] 91 e1 }

  condition:
    any of them
}