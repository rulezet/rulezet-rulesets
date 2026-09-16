rule TTP_XOR_WriteProcessMemory_5b5b {
  strings:
    $key_5b5b = { 0c 29 [2] 3e 0b [2] 38 3e [2] 16 3e [2] 29 22 }

  condition:
    any of them
}