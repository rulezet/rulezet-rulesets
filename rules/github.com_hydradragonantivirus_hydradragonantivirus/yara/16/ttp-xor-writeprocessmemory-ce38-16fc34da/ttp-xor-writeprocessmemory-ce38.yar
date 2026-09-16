rule TTP_XOR_WriteProcessMemory_ce38 {
  strings:
    $key_ce38 = { 99 4a [2] ab 68 [2] ad 5d [2] 83 5d [2] bc 41 }

  condition:
    any of them
}