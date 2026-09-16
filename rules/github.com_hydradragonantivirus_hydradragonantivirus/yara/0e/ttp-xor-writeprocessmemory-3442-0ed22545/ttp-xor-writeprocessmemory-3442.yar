rule TTP_XOR_WriteProcessMemory_3442 {
  strings:
    $key_3442 = { 63 30 [2] 51 12 [2] 57 27 [2] 79 27 [2] 46 3b }

  condition:
    any of them
}