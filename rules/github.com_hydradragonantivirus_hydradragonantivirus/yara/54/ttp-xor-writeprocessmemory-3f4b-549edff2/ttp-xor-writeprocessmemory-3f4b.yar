rule TTP_XOR_WriteProcessMemory_3f4b {
  strings:
    $key_3f4b = { 68 39 [2] 5a 1b [2] 5c 2e [2] 72 2e [2] 4d 32 }

  condition:
    any of them
}