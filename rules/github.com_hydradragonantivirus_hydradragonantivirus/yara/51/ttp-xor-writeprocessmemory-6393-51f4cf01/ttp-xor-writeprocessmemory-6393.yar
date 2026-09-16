rule TTP_XOR_WriteProcessMemory_6393 {
  strings:
    $key_6393 = { 34 e1 [2] 06 c3 [2] 00 f6 [2] 2e f6 [2] 11 ea }

  condition:
    any of them
}