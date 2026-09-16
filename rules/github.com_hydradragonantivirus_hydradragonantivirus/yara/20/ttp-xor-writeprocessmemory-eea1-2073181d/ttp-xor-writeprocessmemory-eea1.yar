rule TTP_XOR_WriteProcessMemory_eea1 {
  strings:
    $key_eea1 = { b9 d3 [2] 8b f1 [2] 8d c4 [2] a3 c4 [2] 9c d8 }

  condition:
    any of them
}