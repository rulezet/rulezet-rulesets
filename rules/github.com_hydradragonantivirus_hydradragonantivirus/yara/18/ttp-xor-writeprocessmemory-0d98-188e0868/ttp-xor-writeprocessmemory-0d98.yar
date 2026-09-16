rule TTP_XOR_WriteProcessMemory_0d98 {
  strings:
    $key_0d98 = { 5a ea [2] 68 c8 [2] 6e fd [2] 40 fd [2] 7f e1 }

  condition:
    any of them
}