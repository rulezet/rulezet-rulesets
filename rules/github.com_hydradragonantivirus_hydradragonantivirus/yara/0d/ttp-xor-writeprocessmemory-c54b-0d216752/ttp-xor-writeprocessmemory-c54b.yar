rule TTP_XOR_WriteProcessMemory_c54b {
  strings:
    $key_c54b = { 92 39 [2] a0 1b [2] a6 2e [2] 88 2e [2] b7 32 }

  condition:
    any of them
}