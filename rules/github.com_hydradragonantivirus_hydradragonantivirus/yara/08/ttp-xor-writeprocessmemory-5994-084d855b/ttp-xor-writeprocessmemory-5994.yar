rule TTP_XOR_WriteProcessMemory_5994 {
  strings:
    $key_5994 = { 0e e6 [2] 3c c4 [2] 3a f1 [2] 14 f1 [2] 2b ed }

  condition:
    any of them
}