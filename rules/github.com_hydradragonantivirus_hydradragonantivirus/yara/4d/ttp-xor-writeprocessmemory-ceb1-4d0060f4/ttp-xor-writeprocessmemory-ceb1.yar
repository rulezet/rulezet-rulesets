rule TTP_XOR_WriteProcessMemory_ceb1 {
  strings:
    $key_ceb1 = { 99 c3 [2] ab e1 [2] ad d4 [2] 83 d4 [2] bc c8 }

  condition:
    any of them
}