rule TTP_XOR_WriteProcessMemory_0050 {
  strings:
    $key_0050 = { 57 22 [2] 65 00 [2] 63 35 [2] 4d 35 [2] 72 29 }

  condition:
    any of them
}