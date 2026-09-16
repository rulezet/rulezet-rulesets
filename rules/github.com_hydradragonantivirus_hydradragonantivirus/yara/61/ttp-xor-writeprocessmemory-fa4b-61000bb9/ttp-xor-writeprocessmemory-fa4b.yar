rule TTP_XOR_WriteProcessMemory_fa4b {
  strings:
    $key_fa4b = { ad 39 [2] 9f 1b [2] 99 2e [2] b7 2e [2] 88 32 }

  condition:
    any of them
}