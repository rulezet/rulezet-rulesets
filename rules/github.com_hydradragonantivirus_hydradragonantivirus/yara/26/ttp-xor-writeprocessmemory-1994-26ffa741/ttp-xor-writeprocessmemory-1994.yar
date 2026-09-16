rule TTP_XOR_WriteProcessMemory_1994 {
  strings:
    $key_1994 = { 4e e6 [2] 7c c4 [2] 7a f1 [2] 54 f1 [2] 6b ed }

  condition:
    any of them
}