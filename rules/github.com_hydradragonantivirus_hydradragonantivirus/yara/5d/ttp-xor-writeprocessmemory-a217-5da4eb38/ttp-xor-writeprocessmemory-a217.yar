rule TTP_XOR_WriteProcessMemory_a217 {
  strings:
    $key_a217 = { f5 65 [2] c7 47 [2] c1 72 [2] ef 72 [2] d0 6e }

  condition:
    any of them
}