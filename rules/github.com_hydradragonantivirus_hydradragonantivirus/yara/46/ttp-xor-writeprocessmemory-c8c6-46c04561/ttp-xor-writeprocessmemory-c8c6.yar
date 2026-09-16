rule TTP_XOR_WriteProcessMemory_c8c6 {
  strings:
    $key_c8c6 = { 9f b4 [2] ad 96 [2] ab a3 [2] 85 a3 [2] ba bf }

  condition:
    any of them
}