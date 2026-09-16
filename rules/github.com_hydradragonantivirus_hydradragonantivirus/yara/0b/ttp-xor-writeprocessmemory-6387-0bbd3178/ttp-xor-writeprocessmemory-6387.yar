rule TTP_XOR_WriteProcessMemory_6387 {
  strings:
    $key_6387 = { 34 f5 [2] 06 d7 [2] 00 e2 [2] 2e e2 [2] 11 fe }

  condition:
    any of them
}