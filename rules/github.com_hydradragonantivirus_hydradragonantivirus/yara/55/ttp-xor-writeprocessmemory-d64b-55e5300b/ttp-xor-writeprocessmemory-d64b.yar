rule TTP_XOR_WriteProcessMemory_d64b {
  strings:
    $key_d64b = { 81 39 [2] b3 1b [2] b5 2e [2] 9b 2e [2] a4 32 }

  condition:
    any of them
}