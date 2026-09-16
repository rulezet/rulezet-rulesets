rule TTP_XOR_WriteProcessMemory_396b {
  strings:
    $key_396b = { 6e 19 [2] 5c 3b [2] 5a 0e [2] 74 0e [2] 4b 12 }

  condition:
    any of them
}