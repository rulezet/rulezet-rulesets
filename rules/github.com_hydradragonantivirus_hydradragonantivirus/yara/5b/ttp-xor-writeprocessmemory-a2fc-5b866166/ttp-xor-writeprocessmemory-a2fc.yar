rule TTP_XOR_WriteProcessMemory_a2fc {
  strings:
    $key_a2fc = { f5 8e [2] c7 ac [2] c1 99 [2] ef 99 [2] d0 85 }

  condition:
    any of them
}