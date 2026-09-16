rule TTP_XOR_WriteProcessMemory_6330 {
  strings:
    $key_6330 = { 34 42 [2] 06 60 [2] 00 55 [2] 2e 55 [2] 11 49 }

  condition:
    any of them
}