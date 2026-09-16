rule TTP_XOR_WriteProcessMemory_4d98 {
  strings:
    $key_4d98 = { 1a ea [2] 28 c8 [2] 2e fd [2] 00 fd [2] 3f e1 }

  condition:
    any of them
}