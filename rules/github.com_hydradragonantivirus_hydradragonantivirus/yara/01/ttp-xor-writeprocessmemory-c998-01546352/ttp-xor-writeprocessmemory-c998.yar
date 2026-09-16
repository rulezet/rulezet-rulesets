rule TTP_XOR_WriteProcessMemory_c998 {
  strings:
    $key_c998 = { 9e ea [2] ac c8 [2] aa fd [2] 84 fd [2] bb e1 }

  condition:
    any of them
}