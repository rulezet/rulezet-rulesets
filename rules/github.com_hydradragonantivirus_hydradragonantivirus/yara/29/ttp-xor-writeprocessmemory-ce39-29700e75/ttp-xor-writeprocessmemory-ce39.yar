rule TTP_XOR_WriteProcessMemory_ce39 {
  strings:
    $key_ce39 = { 99 4b [2] ab 69 [2] ad 5c [2] 83 5c [2] bc 40 }

  condition:
    any of them
}