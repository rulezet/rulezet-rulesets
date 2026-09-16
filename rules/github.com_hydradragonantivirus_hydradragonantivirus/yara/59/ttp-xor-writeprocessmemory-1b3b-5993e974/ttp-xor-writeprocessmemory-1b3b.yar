rule TTP_XOR_WriteProcessMemory_1b3b {
  strings:
    $key_1b3b = { 4c 49 [2] 7e 6b [2] 78 5e [2] 56 5e [2] 69 42 }

  condition:
    any of them
}