rule TTP_XOR_WriteProcessMemory_4994 {
  strings:
    $key_4994 = { 1e e6 [2] 2c c4 [2] 2a f1 [2] 04 f1 [2] 3b ed }

  condition:
    any of them
}