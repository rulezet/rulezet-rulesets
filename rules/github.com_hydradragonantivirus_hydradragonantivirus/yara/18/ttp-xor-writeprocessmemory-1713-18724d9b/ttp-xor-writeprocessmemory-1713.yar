rule TTP_XOR_WriteProcessMemory_1713 {
  strings:
    $key_1713 = { 40 61 [2] 72 43 [2] 74 76 [2] 5a 76 [2] 65 6a }

  condition:
    any of them
}