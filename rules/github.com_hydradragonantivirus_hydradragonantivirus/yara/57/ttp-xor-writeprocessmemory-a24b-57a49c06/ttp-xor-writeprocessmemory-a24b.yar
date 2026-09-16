rule TTP_XOR_WriteProcessMemory_a24b {
  strings:
    $key_a24b = { f5 39 [2] c7 1b [2] c1 2e [2] ef 2e [2] d0 32 }

  condition:
    any of them
}