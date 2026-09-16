rule TTP_XOR_WriteProcessMemory_2098 {
  strings:
    $key_2098 = { 77 ea [2] 45 c8 [2] 43 fd [2] 6d fd [2] 52 e1 }

  condition:
    any of them
}