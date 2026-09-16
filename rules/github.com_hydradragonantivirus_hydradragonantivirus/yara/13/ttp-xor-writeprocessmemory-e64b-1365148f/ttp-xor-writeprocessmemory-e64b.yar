rule TTP_XOR_WriteProcessMemory_e64b {
  strings:
    $key_e64b = { b1 39 [2] 83 1b [2] 85 2e [2] ab 2e [2] 94 32 }

  condition:
    any of them
}