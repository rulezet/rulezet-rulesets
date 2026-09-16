rule TTP_XOR_WriteProcessMemory_3494 {
  strings:
    $key_3494 = { 63 e6 [2] 51 c4 [2] 57 f1 [2] 79 f1 [2] 46 ed }

  condition:
    any of them
}