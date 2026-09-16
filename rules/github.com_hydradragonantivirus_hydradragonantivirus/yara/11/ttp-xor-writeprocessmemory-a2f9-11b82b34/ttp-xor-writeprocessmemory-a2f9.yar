rule TTP_XOR_WriteProcessMemory_a2f9 {
  strings:
    $key_a2f9 = { f5 8b [2] c7 a9 [2] c1 9c [2] ef 9c [2] d0 80 }

  condition:
    any of them
}