rule TTP_XOR_WriteProcessMemory_3b3b {
  strings:
    $key_3b3b = { 6c 49 [2] 5e 6b [2] 58 5e [2] 76 5e [2] 49 42 }

  condition:
    any of them
}