rule TTP_XOR_WriteProcessMemory_c8c0 {
  strings:
    $key_c8c0 = { 9f b2 [2] ad 90 [2] ab a5 [2] 85 a5 [2] ba b9 }

  condition:
    any of them
}