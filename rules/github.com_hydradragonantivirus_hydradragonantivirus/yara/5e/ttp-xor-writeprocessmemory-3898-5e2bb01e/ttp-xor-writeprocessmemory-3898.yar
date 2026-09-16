rule TTP_XOR_WriteProcessMemory_3898 {
  strings:
    $key_3898 = { 6f ea [2] 5d c8 [2] 5b fd [2] 75 fd [2] 4a e1 }

  condition:
    any of them
}