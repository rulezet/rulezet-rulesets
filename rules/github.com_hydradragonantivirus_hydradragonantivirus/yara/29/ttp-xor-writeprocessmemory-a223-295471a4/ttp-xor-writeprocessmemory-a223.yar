rule TTP_XOR_WriteProcessMemory_a223 {
  strings:
    $key_a223 = { f5 51 [2] c7 73 [2] c1 46 [2] ef 46 [2] d0 5a }

  condition:
    any of them
}