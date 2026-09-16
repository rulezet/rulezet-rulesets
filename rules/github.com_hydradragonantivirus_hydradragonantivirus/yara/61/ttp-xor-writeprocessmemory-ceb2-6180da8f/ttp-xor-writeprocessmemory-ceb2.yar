rule TTP_XOR_WriteProcessMemory_ceb2 {
  strings:
    $key_ceb2 = { 99 c0 [2] ab e2 [2] ad d7 [2] 83 d7 [2] bc cb }

  condition:
    any of them
}