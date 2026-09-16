rule TTP_XOR_WriteProcessMemory_00a1 {
  strings:
    $key_00a1 = { 57 d3 [2] 65 f1 [2] 63 c4 [2] 4d c4 [2] 72 d8 }

  condition:
    any of them
}