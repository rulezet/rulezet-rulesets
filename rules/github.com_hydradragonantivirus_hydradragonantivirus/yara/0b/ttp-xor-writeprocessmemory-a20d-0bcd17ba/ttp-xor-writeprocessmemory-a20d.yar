rule TTP_XOR_WriteProcessMemory_a20d {
  strings:
    $key_a20d = { f5 7f [2] c7 5d [2] c1 68 [2] ef 68 [2] d0 74 }

  condition:
    any of them
}