rule TTP_XOR_WriteProcessMemory_a211 {
  strings:
    $key_a211 = { f5 63 [2] c7 41 [2] c1 74 [2] ef 74 [2] d0 68 }

  condition:
    any of them
}