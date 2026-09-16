rule TTP_XOR_WriteProcessMemory_ced5 {
  strings:
    $key_ced5 = { 99 a7 [2] ab 85 [2] ad b0 [2] 83 b0 [2] bc ac }

  condition:
    any of them
}