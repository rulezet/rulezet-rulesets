rule TTP_XOR_WriteProcessMemory_ce14 {
  strings:
    $key_ce14 = { 99 66 [2] ab 44 [2] ad 71 [2] 83 71 [2] bc 6d }

  condition:
    any of them
}