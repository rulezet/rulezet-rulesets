rule TTP_XOR_WriteProcessMemory_7098 {
  strings:
    $key_7098 = { 27 ea [2] 15 c8 [2] 13 fd [2] 3d fd [2] 02 e1 }

  condition:
    any of them
}