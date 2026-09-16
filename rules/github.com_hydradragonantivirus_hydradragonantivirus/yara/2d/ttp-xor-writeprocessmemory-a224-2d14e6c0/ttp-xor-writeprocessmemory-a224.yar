rule TTP_XOR_WriteProcessMemory_a224 {
  strings:
    $key_a224 = { f5 56 [2] c7 74 [2] c1 41 [2] ef 41 [2] d0 5d }

  condition:
    any of them
}