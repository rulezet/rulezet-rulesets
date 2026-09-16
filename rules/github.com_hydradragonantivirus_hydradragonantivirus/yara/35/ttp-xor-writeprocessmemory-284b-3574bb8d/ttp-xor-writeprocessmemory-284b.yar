rule TTP_XOR_WriteProcessMemory_284b {
  strings:
    $key_284b = { 7f 39 [2] 4d 1b [2] 4b 2e [2] 65 2e [2] 5a 32 }

  condition:
    any of them
}