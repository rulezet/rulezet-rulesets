rule TTP_XOR_WriteProcessMemory_3450 {
  strings:
    $key_3450 = { 63 22 [2] 51 00 [2] 57 35 [2] 79 35 [2] 46 29 }

  condition:
    any of them
}