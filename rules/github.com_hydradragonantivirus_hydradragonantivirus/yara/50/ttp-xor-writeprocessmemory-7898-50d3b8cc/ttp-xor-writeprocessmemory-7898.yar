rule TTP_XOR_WriteProcessMemory_7898 {
  strings:
    $key_7898 = { 2f ea [2] 1d c8 [2] 1b fd [2] 35 fd [2] 0a e1 }

  condition:
    any of them
}