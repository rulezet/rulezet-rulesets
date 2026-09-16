rule TTP_XOR_WriteProcessMemory_6c5b {
  strings:
    $key_6c5b = { 3b 29 [2] 09 0b [2] 0f 3e [2] 21 3e [2] 1e 22 }

  condition:
    any of them
}