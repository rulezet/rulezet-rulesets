rule TTP_XOR_WriteProcessMemory_3994 {
  strings:
    $key_3994 = { 6e e6 [2] 5c c4 [2] 5a f1 [2] 74 f1 [2] 4b ed }

  condition:
    any of them
}