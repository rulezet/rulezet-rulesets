rule TTP_XOR_WriteProcessMemory_1142 {
  strings:
    $key_1142 = { 46 30 [2] 74 12 [2] 72 27 [2] 5c 27 [2] 63 3b }

  condition:
    any of them
}