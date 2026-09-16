rule TTP_XOR_WriteProcessMemory_ecf1 {
  strings:
    $key_ecf1 = { bb 83 [2] 89 a1 [2] 8f 94 [2] a1 94 [2] 9e 88 }

  condition:
    any of them
}