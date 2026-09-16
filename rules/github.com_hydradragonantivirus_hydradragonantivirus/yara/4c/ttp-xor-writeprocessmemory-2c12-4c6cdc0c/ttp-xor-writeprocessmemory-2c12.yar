rule TTP_XOR_WriteProcessMemory_2c12 {
  strings:
    $key_2c12 = { 7b 60 [2] 49 42 [2] 4f 77 [2] 61 77 [2] 5e 6b }

  condition:
    any of them
}