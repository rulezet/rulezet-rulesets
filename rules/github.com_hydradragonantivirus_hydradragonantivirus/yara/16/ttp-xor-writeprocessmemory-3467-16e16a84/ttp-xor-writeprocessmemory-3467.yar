rule TTP_XOR_WriteProcessMemory_3467 {
  strings:
    $key_3467 = { 63 15 [2] 51 37 [2] 57 02 [2] 79 02 [2] 46 1e }

  condition:
    any of them
}