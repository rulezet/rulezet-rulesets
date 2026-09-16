rule TTP_XOR_WriteProcessMemory_094b {
  strings:
    $key_094b = { 5e 39 [2] 6c 1b [2] 6a 2e [2] 44 2e [2] 7b 32 }

  condition:
    any of them
}