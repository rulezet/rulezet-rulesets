rule TTP_XOR_WriteProcessMemory_a655 {
  strings:
    $key_a655 = { f1 27 [2] c3 05 [2] c5 30 [2] eb 30 [2] d4 2c }

  condition:
    any of them
}