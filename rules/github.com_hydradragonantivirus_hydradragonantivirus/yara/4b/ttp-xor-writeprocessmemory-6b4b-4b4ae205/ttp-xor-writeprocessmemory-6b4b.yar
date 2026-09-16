rule TTP_XOR_WriteProcessMemory_6b4b {
  strings:
    $key_6b4b = { 3c 39 [2] 0e 1b [2] 08 2e [2] 26 2e [2] 19 32 }

  condition:
    any of them
}