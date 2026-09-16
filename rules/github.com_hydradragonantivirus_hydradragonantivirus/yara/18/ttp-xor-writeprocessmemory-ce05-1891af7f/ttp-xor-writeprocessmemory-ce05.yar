rule TTP_XOR_WriteProcessMemory_ce05 {
  strings:
    $key_ce05 = { 99 77 [2] ab 55 [2] ad 60 [2] 83 60 [2] bc 7c }

  condition:
    any of them
}