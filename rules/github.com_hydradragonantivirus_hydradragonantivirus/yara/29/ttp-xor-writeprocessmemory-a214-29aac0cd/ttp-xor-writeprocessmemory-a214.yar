rule TTP_XOR_WriteProcessMemory_a214 {
  strings:
    $key_a214 = { f5 66 [2] c7 44 [2] c1 71 [2] ef 71 [2] d0 6d }

  condition:
    any of them
}