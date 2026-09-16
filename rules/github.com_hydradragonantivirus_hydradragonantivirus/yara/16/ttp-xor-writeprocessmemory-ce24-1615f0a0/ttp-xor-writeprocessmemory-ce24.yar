rule TTP_XOR_WriteProcessMemory_ce24 {
  strings:
    $key_ce24 = { 99 56 [2] ab 74 [2] ad 41 [2] 83 41 [2] bc 5d }

  condition:
    any of them
}