rule TTP_XOR_WriteProcessMemory_ce01 {
  strings:
    $key_ce01 = { 99 73 [2] ab 51 [2] ad 64 [2] 83 64 [2] bc 78 }

  condition:
    any of them
}