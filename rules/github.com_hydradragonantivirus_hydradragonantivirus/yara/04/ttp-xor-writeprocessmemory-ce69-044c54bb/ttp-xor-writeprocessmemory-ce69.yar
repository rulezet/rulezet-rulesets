rule TTP_XOR_WriteProcessMemory_ce69 {
  strings:
    $key_ce69 = { 99 1b [2] ab 39 [2] ad 0c [2] 83 0c [2] bc 10 }

  condition:
    any of them
}