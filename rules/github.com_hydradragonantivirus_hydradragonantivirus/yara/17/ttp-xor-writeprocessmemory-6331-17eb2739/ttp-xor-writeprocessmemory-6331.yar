rule TTP_XOR_WriteProcessMemory_6331 {
  strings:
    $key_6331 = { 34 43 [2] 06 61 [2] 00 54 [2] 2e 54 [2] 11 48 }

  condition:
    any of them
}