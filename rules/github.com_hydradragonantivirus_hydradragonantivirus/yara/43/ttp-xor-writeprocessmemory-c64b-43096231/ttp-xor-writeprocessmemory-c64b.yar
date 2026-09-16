rule TTP_XOR_WriteProcessMemory_c64b {
  strings:
    $key_c64b = { 91 39 [2] a3 1b [2] a5 2e [2] 8b 2e [2] b4 32 }

  condition:
    any of them
}