rule TTP_XOR_WriteProcessMemory_1131 {
  strings:
    $key_1131 = { 46 43 [2] 74 61 [2] 72 54 [2] 5c 54 [2] 63 48 }

  condition:
    any of them
}