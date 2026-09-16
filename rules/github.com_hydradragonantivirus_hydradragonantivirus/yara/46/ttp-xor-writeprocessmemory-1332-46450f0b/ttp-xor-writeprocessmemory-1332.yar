rule TTP_XOR_WriteProcessMemory_1332 {
  strings:
    $key_1332 = { 44 40 [2] 76 62 [2] 70 57 [2] 5e 57 [2] 61 4b }

  condition:
    any of them
}