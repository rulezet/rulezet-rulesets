rule TTP_XOR_WriteProcessMemory_4102 {
  strings:
    $key_4102 = { 16 70 [2] 24 52 [2] 22 67 [2] 0c 67 [2] 33 7b }

  condition:
    any of them
}