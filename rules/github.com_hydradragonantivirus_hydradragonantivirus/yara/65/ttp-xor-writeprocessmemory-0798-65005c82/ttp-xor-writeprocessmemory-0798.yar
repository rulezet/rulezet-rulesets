rule TTP_XOR_WriteProcessMemory_0798 {
  strings:
    $key_0798 = { 50 ea [2] 62 c8 [2] 64 fd [2] 4a fd [2] 75 e1 }

  condition:
    any of them
}