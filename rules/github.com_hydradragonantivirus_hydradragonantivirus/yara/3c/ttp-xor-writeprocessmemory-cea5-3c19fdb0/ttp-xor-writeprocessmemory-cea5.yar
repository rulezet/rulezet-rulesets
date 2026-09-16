rule TTP_XOR_WriteProcessMemory_cea5 {
  strings:
    $key_cea5 = { 99 d7 [2] ab f5 [2] ad c0 [2] 83 c0 [2] bc dc }

  condition:
    any of them
}