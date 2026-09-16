rule TTP_XOR_WriteProcessMemory_c8e6 {
  strings:
    $key_c8e6 = { 9f 94 [2] ad b6 [2] ab 83 [2] 85 83 [2] ba 9f }

  condition:
    any of them
}