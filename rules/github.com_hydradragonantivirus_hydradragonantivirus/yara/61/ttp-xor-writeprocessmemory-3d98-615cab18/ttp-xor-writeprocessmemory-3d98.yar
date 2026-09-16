rule TTP_XOR_WriteProcessMemory_3d98 {
  strings:
    $key_3d98 = { 6a ea [2] 58 c8 [2] 5e fd [2] 70 fd [2] 4f e1 }

  condition:
    any of them
}