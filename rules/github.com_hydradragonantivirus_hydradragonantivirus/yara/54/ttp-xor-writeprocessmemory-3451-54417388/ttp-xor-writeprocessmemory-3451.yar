rule TTP_XOR_WriteProcessMemory_3451 {
  strings:
    $key_3451 = { 63 23 [2] 51 01 [2] 57 34 [2] 79 34 [2] 46 28 }

  condition:
    any of them
}