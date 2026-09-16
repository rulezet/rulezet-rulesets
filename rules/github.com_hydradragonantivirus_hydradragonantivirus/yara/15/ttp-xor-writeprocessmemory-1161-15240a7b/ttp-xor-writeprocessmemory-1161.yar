rule TTP_XOR_WriteProcessMemory_1161 {
  strings:
    $key_1161 = { 46 13 [2] 74 31 [2] 72 04 [2] 5c 04 [2] 63 18 }

  condition:
    any of them
}