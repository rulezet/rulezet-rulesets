rule TTP_XOR_WriteProcessMemory_5913 {
  strings:
    $key_5913 = { 0e 61 [2] 3c 43 [2] 3a 76 [2] 14 76 [2] 2b 6a }

  condition:
    any of them
}