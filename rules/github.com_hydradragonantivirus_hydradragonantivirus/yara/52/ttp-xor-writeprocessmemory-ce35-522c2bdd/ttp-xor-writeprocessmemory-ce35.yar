rule TTP_XOR_WriteProcessMemory_ce35 {
  strings:
    $key_ce35 = { 99 47 [2] ab 65 [2] ad 50 [2] 83 50 [2] bc 4c }

  condition:
    any of them
}