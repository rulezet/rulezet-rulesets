rule TTP_XOR_WriteProcessMemory_ceed {
  strings:
    $key_ceed = { 99 9f [2] ab bd [2] ad 88 [2] 83 88 [2] bc 94 }

  condition:
    any of them
}