rule TTP_XOR_WriteProcessMemory_224b {
  strings:
    $key_224b = { 75 39 [2] 47 1b [2] 41 2e [2] 6f 2e [2] 50 32 }

  condition:
    any of them
}