rule TTP_XOR_WriteProcessMemory_63c8 {
  strings:
    $key_63c8 = { 34 ba [2] 06 98 [2] 00 ad [2] 2e ad [2] 11 b1 }

  condition:
    any of them
}