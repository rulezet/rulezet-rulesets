rule TTP_XOR_WriteProcessMemory_8da1 {
  strings:
    $key_8da1 = { da d3 [2] e8 f1 [2] ee c4 [2] c0 c4 [2] ff d8 }

  condition:
    any of them
}