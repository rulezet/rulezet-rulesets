rule TTP_XOR_WriteProcessMemory_ced2 {
  strings:
    $key_ced2 = { 99 a0 [2] ab 82 [2] ad b7 [2] 83 b7 [2] bc ab }

  condition:
    any of them
}