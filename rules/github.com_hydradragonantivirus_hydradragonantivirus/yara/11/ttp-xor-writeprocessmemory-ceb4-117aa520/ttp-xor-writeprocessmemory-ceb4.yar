rule TTP_XOR_WriteProcessMemory_ceb4 {
  strings:
    $key_ceb4 = { 99 c6 [2] ab e4 [2] ad d1 [2] 83 d1 [2] bc cd }

  condition:
    any of them
}