rule TTP_XOR_WriteProcessMemory_7150 {
  strings:
    $key_7150 = { 26 22 [2] 14 00 [2] 12 35 [2] 3c 35 [2] 03 29 }

  condition:
    any of them
}