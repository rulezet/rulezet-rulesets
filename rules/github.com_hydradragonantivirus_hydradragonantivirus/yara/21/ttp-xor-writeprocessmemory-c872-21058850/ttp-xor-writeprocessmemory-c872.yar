rule TTP_XOR_WriteProcessMemory_c872 {
  strings:
    $key_c872 = { 9f 00 [2] ad 22 [2] ab 17 [2] 85 17 [2] ba 0b }

  condition:
    any of them
}