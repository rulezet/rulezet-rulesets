rule TTP_XOR_WriteProcessMemory_50f1 {
  strings:
    $key_50f1 = { 07 83 [2] 35 a1 [2] 33 94 [2] 1d 94 [2] 22 88 }

  condition:
    any of them
}