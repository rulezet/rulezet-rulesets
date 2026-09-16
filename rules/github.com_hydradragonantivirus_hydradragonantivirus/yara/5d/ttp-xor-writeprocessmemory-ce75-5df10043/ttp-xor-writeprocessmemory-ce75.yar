rule TTP_XOR_WriteProcessMemory_ce75 {
  strings:
    $key_ce75 = { 99 07 [2] ab 25 [2] ad 10 [2] 83 10 [2] bc 0c }

  condition:
    any of them
}