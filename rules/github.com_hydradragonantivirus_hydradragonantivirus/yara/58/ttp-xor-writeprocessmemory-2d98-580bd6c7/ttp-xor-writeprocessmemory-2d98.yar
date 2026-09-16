rule TTP_XOR_WriteProcessMemory_2d98 {
  strings:
    $key_2d98 = { 7a ea [2] 48 c8 [2] 4e fd [2] 60 fd [2] 5f e1 }

  condition:
    any of them
}