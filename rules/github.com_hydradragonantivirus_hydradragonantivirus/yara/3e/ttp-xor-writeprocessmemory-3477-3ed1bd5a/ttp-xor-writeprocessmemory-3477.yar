rule TTP_XOR_WriteProcessMemory_3477 {
  strings:
    $key_3477 = { 63 05 [2] 51 27 [2] 57 12 [2] 79 12 [2] 46 0e }

  condition:
    any of them
}