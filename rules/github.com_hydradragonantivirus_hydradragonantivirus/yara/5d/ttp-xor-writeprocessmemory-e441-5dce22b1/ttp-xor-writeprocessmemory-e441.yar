rule TTP_XOR_WriteProcessMemory_e441 {
  strings:
    $key_e441 = { b3 33 [2] 81 11 [2] 87 24 [2] a9 24 [2] 96 38 }

  condition:
    any of them
}