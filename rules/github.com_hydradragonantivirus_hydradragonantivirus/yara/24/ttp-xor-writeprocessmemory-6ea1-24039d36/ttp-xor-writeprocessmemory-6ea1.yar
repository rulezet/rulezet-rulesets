rule TTP_XOR_WriteProcessMemory_6ea1 {
  strings:
    $key_6ea1 = { 39 d3 [2] 0b f1 [2] 0d c4 [2] 23 c4 [2] 1c d8 }

  condition:
    any of them
}