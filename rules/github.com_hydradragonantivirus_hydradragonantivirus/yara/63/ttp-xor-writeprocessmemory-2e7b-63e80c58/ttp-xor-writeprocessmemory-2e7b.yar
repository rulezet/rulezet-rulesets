rule TTP_XOR_WriteProcessMemory_2e7b {
  strings:
    $key_2e7b = { 79 09 [2] 4b 2b [2] 4d 1e [2] 63 1e [2] 5c 02 }

  condition:
    any of them
}