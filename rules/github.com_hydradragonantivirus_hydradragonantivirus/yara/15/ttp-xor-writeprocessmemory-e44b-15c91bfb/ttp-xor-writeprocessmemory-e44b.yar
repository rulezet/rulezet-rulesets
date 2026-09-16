rule TTP_XOR_WriteProcessMemory_e44b {
  strings:
    $key_e44b = { b3 39 [2] 81 1b [2] 87 2e [2] a9 2e [2] 96 32 }

  condition:
    any of them
}