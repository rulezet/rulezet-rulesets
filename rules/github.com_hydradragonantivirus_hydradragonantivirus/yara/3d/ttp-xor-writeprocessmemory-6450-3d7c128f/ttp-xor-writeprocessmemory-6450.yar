rule TTP_XOR_WriteProcessMemory_6450 {
  strings:
    $key_6450 = { 33 22 [2] 01 00 [2] 07 35 [2] 29 35 [2] 16 29 }

  condition:
    any of them
}