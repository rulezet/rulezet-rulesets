rule TTP_XOR_WriteProcessMemory_5765 {
  strings:
    $key_5765 = { 00 17 [2] 32 35 [2] 34 00 [2] 1a 00 [2] 25 1c }

  condition:
    any of them
}