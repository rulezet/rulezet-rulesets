rule TTP_XOR_WriteProcessMemory_310b {
  strings:
    $key_310b = { 66 79 [2] 54 5b [2] 52 6e [2] 7c 6e [2] 43 72 }

  condition:
    any of them
}