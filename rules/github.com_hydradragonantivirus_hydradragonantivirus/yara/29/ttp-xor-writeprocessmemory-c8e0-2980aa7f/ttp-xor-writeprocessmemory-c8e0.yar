rule TTP_XOR_WriteProcessMemory_c8e0 {
  strings:
    $key_c8e0 = { 9f 92 [2] ad b0 [2] ab 85 [2] 85 85 [2] ba 99 }

  condition:
    any of them
}