rule TTP_XOR_WriteProcessMemory_294b {
  strings:
    $key_294b = { 7e 39 [2] 4c 1b [2] 4a 2e [2] 64 2e [2] 5b 32 }

  condition:
    any of them
}