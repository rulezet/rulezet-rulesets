rule TTP_XOR_WriteProcessMemory_ceb5 {
  strings:
    $key_ceb5 = { 99 c7 [2] ab e5 [2] ad d0 [2] 83 d0 [2] bc cc }

  condition:
    any of them
}