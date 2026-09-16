rule TTP_XOR_WriteProcessMemory_0498 {
  strings:
    $key_0498 = { 53 ea [2] 61 c8 [2] 67 fd [2] 49 fd [2] 76 e1 }

  condition:
    any of them
}