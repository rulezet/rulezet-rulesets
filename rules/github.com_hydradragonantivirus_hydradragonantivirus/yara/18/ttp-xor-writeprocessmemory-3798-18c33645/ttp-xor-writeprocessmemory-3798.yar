rule TTP_XOR_WriteProcessMemory_3798 {
  strings:
    $key_3798 = { 60 ea [2] 52 c8 [2] 54 fd [2] 7a fd [2] 45 e1 }

  condition:
    any of them
}