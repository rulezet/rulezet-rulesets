rule TTP_XOR_WriteProcessMemory_1377 {
  strings:
    $key_1377 = { 44 05 [2] 76 27 [2] 70 12 [2] 5e 12 [2] 61 0e }

  condition:
    any of them
}