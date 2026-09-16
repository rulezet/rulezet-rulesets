rule TTP_XOR_WriteProcessMemory_a21b {
  strings:
    $key_a21b = { f5 69 [2] c7 4b [2] c1 7e [2] ef 7e [2] d0 62 }

  condition:
    any of them
}