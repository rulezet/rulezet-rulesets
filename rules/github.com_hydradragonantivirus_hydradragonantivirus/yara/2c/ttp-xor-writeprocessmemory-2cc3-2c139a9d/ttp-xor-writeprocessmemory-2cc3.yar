rule TTP_XOR_WriteProcessMemory_2cc3 {
  strings:
    $key_2cc3 = { 7b b1 [2] 49 93 [2] 4f a6 [2] 61 a6 [2] 5e ba }

  condition:
    any of them
}