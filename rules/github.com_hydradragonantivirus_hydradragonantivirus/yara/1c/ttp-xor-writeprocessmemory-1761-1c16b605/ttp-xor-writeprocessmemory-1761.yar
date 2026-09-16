rule TTP_XOR_WriteProcessMemory_1761 {
  strings:
    $key_1761 = { 40 13 [2] 72 31 [2] 74 04 [2] 5a 04 [2] 65 18 }

  condition:
    any of them
}