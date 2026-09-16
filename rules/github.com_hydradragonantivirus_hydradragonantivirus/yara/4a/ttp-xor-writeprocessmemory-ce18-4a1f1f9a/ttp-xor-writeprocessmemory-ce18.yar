rule TTP_XOR_WriteProcessMemory_ce18 {
  strings:
    $key_ce18 = { 99 6a [2] ab 48 [2] ad 7d [2] 83 7d [2] bc 61 }

  condition:
    any of them
}