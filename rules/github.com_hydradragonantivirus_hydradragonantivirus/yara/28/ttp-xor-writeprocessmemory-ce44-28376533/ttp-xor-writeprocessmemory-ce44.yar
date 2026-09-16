rule TTP_XOR_WriteProcessMemory_ce44 {
  strings:
    $key_ce44 = { 99 36 [2] ab 14 [2] ad 21 [2] 83 21 [2] bc 3d }

  condition:
    any of them
}