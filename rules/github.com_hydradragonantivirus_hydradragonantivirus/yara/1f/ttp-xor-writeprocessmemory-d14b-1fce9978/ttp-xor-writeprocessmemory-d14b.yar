rule TTP_XOR_WriteProcessMemory_d14b {
  strings:
    $key_d14b = { 86 39 [2] b4 1b [2] b2 2e [2] 9c 2e [2] a3 32 }

  condition:
    any of them
}