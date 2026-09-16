rule TTP_XOR_WriteProcessMemory_23f1 {
  strings:
    $key_23f1 = { 74 83 [2] 46 a1 [2] 40 94 [2] 6e 94 [2] 51 88 }

  condition:
    any of them
}