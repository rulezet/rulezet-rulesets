rule TTP_XOR_WriteProcessMemory_ce15 {
  strings:
    $key_ce15 = { 99 67 [2] ab 45 [2] ad 70 [2] 83 70 [2] bc 6c }

  condition:
    any of them
}