rule TTP_XOR_WriteProcessMemory_1365 {
  strings:
    $key_1365 = { 44 17 [2] 76 35 [2] 70 00 [2] 5e 00 [2] 61 1c }

  condition:
    any of them
}