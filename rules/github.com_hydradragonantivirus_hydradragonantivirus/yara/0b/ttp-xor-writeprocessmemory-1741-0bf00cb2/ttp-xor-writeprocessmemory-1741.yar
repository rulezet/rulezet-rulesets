rule TTP_XOR_WriteProcessMemory_1741 {
  strings:
    $key_1741 = { 40 33 [2] 72 11 [2] 74 24 [2] 5a 24 [2] 65 38 }

  condition:
    any of them
}