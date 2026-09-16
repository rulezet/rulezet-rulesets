rule TTP_XOR_WriteProcessMemory_ceb0 {
  strings:
    $key_ceb0 = { 99 c2 [2] ab e0 [2] ad d5 [2] 83 d5 [2] bc c9 }

  condition:
    any of them
}