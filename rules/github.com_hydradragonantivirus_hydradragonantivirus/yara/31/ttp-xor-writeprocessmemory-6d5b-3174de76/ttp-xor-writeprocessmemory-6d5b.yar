rule TTP_XOR_WriteProcessMemory_6d5b {
  strings:
    $key_6d5b = { 3a 29 [2] 08 0b [2] 0e 3e [2] 20 3e [2] 1f 22 }

  condition:
    any of them
}