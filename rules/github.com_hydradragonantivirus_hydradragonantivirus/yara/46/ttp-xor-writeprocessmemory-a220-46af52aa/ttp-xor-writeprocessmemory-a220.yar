rule TTP_XOR_WriteProcessMemory_a220 {
  strings:
    $key_a220 = { f5 52 [2] c7 70 [2] c1 45 [2] ef 45 [2] d0 59 }

  condition:
    any of them
}