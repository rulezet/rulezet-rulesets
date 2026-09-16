rule TTP_XOR_WriteProcessMemory_a055 {
  strings:
    $key_a055 = { f7 27 [2] c5 05 [2] c3 30 [2] ed 30 [2] d2 2c }

  condition:
    any of them
}