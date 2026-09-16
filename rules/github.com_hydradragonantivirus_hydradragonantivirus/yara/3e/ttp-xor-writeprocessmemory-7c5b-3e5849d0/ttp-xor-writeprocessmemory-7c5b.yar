rule TTP_XOR_WriteProcessMemory_7c5b {
  strings:
    $key_7c5b = { 2b 29 [2] 19 0b [2] 1f 3e [2] 31 3e [2] 0e 22 }

  condition:
    any of them
}