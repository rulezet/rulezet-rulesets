rule TTP_XOR_WriteProcessMemory_734b {
  strings:
    $key_734b = { 24 39 [2] 16 1b [2] 10 2e [2] 3e 2e [2] 01 32 }

  condition:
    any of them
}