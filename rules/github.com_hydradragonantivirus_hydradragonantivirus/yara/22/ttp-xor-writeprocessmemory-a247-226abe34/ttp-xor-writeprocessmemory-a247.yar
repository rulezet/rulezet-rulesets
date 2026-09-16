rule TTP_XOR_WriteProcessMemory_a247 {
  strings:
    $key_a247 = { f5 35 [2] c7 17 [2] c1 22 [2] ef 22 [2] d0 3e }

  condition:
    any of them
}