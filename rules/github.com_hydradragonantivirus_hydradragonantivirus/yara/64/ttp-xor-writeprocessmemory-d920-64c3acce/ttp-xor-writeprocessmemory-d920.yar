rule TTP_XOR_WriteProcessMemory_d920 {
  strings:
    $key_d920 = { 8e 52 [2] bc 70 [2] ba 45 [2] 94 45 [2] ab 59 }

  condition:
    any of them
}