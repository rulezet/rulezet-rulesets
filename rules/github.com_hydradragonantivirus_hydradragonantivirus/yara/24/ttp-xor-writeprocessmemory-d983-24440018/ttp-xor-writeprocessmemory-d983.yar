rule TTP_XOR_WriteProcessMemory_d983 {
  strings:
    $key_d983 = { 8e f1 [2] bc d3 [2] ba e6 [2] 94 e6 [2] ab fa }

  condition:
    any of them
}