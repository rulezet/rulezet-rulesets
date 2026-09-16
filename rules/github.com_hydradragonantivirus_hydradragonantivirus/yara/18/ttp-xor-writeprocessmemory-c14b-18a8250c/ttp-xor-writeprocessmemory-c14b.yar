rule TTP_XOR_WriteProcessMemory_c14b {
  strings:
    $key_c14b = { 96 39 [2] a4 1b [2] a2 2e [2] 8c 2e [2] b3 32 }

  condition:
    any of them
}