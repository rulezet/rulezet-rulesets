rule TTP_XOR_WriteProcessMemory_c860 {
  strings:
    $key_c860 = { 9f 12 [2] ad 30 [2] ab 05 [2] 85 05 [2] ba 19 }

  condition:
    any of them
}