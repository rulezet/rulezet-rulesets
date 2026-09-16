rule TTP_XOR_WriteProcessMemory_0cc3 {
  strings:
    $key_0cc3 = { 5b b1 [2] 69 93 [2] 6f a6 [2] 41 a6 [2] 7e ba }

  condition:
    any of them
}