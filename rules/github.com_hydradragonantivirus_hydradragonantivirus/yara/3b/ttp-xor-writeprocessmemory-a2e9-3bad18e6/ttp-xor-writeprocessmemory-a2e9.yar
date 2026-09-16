rule TTP_XOR_WriteProcessMemory_a2e9 {
  strings:
    $key_a2e9 = { f5 9b [2] c7 b9 [2] c1 8c [2] ef 8c [2] d0 90 }

  condition:
    any of them
}