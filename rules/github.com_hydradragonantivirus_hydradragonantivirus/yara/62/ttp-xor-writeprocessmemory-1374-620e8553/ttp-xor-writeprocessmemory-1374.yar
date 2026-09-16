rule TTP_XOR_WriteProcessMemory_1374 {
  strings:
    $key_1374 = { 44 06 [2] 76 24 [2] 70 11 [2] 5e 11 [2] 61 0d }

  condition:
    any of them
}