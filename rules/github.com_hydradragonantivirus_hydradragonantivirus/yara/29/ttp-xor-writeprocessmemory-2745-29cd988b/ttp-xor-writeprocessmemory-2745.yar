rule TTP_XOR_WriteProcessMemory_2745 {
  strings:
    $key_2745 = { 70 37 [2] 42 15 [2] 44 20 [2] 6a 20 [2] 55 3c }

  condition:
    any of them
}