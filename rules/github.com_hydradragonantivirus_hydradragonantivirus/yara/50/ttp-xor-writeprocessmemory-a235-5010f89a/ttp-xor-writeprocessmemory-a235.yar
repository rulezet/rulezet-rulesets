rule TTP_XOR_WriteProcessMemory_a235 {
  strings:
    $key_a235 = { f5 47 [2] c7 65 [2] c1 50 [2] ef 50 [2] d0 4c }

  condition:
    any of them
}