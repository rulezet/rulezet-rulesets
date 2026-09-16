rule TTP_XOR_WriteProcessMemory_68a1 {
  strings:
    $key_68a1 = { 3f d3 [2] 0d f1 [2] 0b c4 [2] 25 c4 [2] 1a d8 }

  condition:
    any of them
}