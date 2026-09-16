rule TTP_XOR_WriteProcessMemory_d467 {
  strings:
    $key_d467 = { 83 15 [2] b1 37 [2] b7 02 [2] 99 02 [2] a6 1e }

  condition:
    any of them
}