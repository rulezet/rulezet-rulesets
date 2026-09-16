rule TTP_XOR_WriteProcessMemory_ce16 {
  strings:
    $key_ce16 = { 99 64 [2] ab 46 [2] ad 73 [2] 83 73 [2] bc 6f }

  condition:
    any of them
}