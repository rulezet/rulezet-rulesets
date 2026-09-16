rule TTP_XOR_WriteProcessMemory_c851 {
  strings:
    $key_c851 = { 9f 23 [2] ad 01 [2] ab 34 [2] 85 34 [2] ba 28 }

  condition:
    any of them
}