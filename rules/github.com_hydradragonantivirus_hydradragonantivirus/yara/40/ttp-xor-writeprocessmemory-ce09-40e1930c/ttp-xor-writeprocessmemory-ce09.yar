rule TTP_XOR_WriteProcessMemory_ce09 {
  strings:
    $key_ce09 = { 99 7b [2] ab 59 [2] ad 6c [2] 83 6c [2] bc 70 }

  condition:
    any of them
}