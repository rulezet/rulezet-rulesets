rule TTP_XOR_WriteProcessMemory_b74b {
  strings:
    $key_b74b = { e0 39 [2] d2 1b [2] d4 2e [2] fa 2e [2] c5 32 }

  condition:
    any of them
}