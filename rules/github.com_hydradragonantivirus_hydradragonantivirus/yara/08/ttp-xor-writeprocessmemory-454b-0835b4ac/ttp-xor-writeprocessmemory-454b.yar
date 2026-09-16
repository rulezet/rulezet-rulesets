rule TTP_XOR_WriteProcessMemory_454b {
  strings:
    $key_454b = { 12 39 [2] 20 1b [2] 26 2e [2] 08 2e [2] 37 32 }

  condition:
    any of them
}