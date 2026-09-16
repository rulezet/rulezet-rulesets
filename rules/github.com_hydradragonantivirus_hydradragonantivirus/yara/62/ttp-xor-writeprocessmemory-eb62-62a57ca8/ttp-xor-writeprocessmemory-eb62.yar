rule TTP_XOR_WriteProcessMemory_eb62 {
  strings:
    $key_eb62 = { bc 10 [2] 8e 32 [2] 88 07 [2] a6 07 [2] 99 1b }

  condition:
    any of them
}