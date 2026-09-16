rule TTP_XOR_WriteProcessMemory_a2f4 {
  strings:
    $key_a2f4 = { f5 86 [2] c7 a4 [2] c1 91 [2] ef 91 [2] d0 8d }

  condition:
    any of them
}