rule TTP_XOR_WriteProcessMemory_c890 {
  strings:
    $key_c890 = { 9f e2 [2] ad c0 [2] ab f5 [2] 85 f5 [2] ba e9 }

  condition:
    any of them
}