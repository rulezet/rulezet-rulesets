rule TTP_XOR_WriteProcessMemory_174b {
  strings:
    $key_174b = { 40 39 [2] 72 1b [2] 74 2e [2] 5a 2e [2] 65 32 }

  condition:
    any of them
}