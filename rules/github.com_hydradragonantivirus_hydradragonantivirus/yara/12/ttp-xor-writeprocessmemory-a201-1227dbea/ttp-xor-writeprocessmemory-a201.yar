rule TTP_XOR_WriteProcessMemory_a201 {
  strings:
    $key_a201 = { f5 73 [2] c7 51 [2] c1 64 [2] ef 64 [2] d0 78 }

  condition:
    any of them
}