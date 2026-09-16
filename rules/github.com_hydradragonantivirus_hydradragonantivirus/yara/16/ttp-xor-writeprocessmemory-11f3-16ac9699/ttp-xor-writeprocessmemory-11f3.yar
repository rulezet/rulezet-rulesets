rule TTP_XOR_WriteProcessMemory_11f3 {
  strings:
    $key_11f3 = { 46 81 [2] 74 a3 [2] 72 96 [2] 5c 96 [2] 63 8a }

  condition:
    any of them
}