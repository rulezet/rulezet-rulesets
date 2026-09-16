rule TTP_XOR_WriteProcessMemory_ced6 {
  strings:
    $key_ced6 = { 99 a4 [2] ab 86 [2] ad b3 [2] 83 b3 [2] bc af }

  condition:
    any of them
}