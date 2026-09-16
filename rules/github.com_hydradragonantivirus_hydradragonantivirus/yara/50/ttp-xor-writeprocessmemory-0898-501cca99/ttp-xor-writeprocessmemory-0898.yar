rule TTP_XOR_WriteProcessMemory_0898 {
  strings:
    $key_0898 = { 5f ea [2] 6d c8 [2] 6b fd [2] 45 fd [2] 7a e1 }

  condition:
    any of them
}