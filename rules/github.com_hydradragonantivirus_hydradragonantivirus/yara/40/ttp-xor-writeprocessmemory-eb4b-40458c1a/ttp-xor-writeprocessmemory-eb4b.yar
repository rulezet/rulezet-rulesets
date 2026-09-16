rule TTP_XOR_WriteProcessMemory_eb4b {
  strings:
    $key_eb4b = { bc 39 [2] 8e 1b [2] 88 2e [2] a6 2e [2] 99 32 }

  condition:
    any of them
}