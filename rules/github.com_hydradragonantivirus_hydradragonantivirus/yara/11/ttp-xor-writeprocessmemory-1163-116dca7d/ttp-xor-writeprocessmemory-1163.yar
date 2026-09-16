rule TTP_XOR_WriteProcessMemory_1163 {
  strings:
    $key_1163 = { 46 11 [2] 74 33 [2] 72 06 [2] 5c 06 [2] 63 1a }

  condition:
    any of them
}