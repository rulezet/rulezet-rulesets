rule TTP_XOR_WriteProcessMemory_ce26 {
  strings:
    $key_ce26 = { 99 54 [2] ab 76 [2] ad 43 [2] 83 43 [2] bc 5f }

  condition:
    any of them
}