rule TTP_XOR_WriteProcessMemory_a232 {
  strings:
    $key_a232 = { f5 40 [2] c7 62 [2] c1 57 [2] ef 57 [2] d0 4b }

  condition:
    any of them
}