rule TTP_XOR_WriteProcessMemory_1141 {
  strings:
    $key_1141 = { 46 33 [2] 74 11 [2] 72 24 [2] 5c 24 [2] 63 38 }

  condition:
    any of them
}