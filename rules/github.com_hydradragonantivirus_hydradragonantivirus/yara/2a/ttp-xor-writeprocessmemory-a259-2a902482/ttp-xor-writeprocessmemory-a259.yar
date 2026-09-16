rule TTP_XOR_WriteProcessMemory_a259 {
  strings:
    $key_a259 = { f5 2b [2] c7 09 [2] c1 3c [2] ef 3c [2] d0 20 }

  condition:
    any of them
}