rule TTP_XOR_WriteProcessMemory_a205 {
  strings:
    $key_a205 = { f5 77 [2] c7 55 [2] c1 60 [2] ef 60 [2] d0 7c }

  condition:
    any of them
}