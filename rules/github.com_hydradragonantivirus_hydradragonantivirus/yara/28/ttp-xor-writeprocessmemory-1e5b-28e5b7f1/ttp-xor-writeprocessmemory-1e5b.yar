rule TTP_XOR_WriteProcessMemory_1e5b {
  strings:
    $key_1e5b = { 49 29 [2] 7b 0b [2] 7d 3e [2] 53 3e [2] 6c 22 }

  condition:
    any of them
}