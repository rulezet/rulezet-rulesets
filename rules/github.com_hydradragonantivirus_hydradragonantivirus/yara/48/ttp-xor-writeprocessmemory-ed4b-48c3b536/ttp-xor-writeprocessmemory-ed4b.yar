rule TTP_XOR_WriteProcessMemory_ed4b {
  strings:
    $key_ed4b = { ba 39 [2] 88 1b [2] 8e 2e [2] a0 2e [2] 9f 32 }

  condition:
    any of them
}