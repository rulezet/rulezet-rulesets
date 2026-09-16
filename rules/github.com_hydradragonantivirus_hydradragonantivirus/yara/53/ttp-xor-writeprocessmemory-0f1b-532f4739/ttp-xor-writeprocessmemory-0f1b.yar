rule TTP_XOR_WriteProcessMemory_0f1b {
  strings:
    $key_0f1b = { 58 69 [2] 6a 4b [2] 6c 7e [2] 42 7e [2] 7d 62 }

  condition:
    any of them
}