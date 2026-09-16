rule TTP_XOR_WriteProcessMemory_cec5 {
  strings:
    $key_cec5 = { 99 b7 [2] ab 95 [2] ad a0 [2] 83 a0 [2] bc bc }

  condition:
    any of them
}