rule TTP_XOR_WriteProcessMemory_3ea1 {
  strings:
    $key_3ea1 = { 69 d3 [2] 5b f1 [2] 5d c4 [2] 73 c4 [2] 4c d8 }

  condition:
    any of them
}