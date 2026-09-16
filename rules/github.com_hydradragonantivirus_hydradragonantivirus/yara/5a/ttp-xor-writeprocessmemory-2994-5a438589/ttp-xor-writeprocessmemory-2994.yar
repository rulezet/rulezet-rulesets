rule TTP_XOR_WriteProcessMemory_2994 {
  strings:
    $key_2994 = { 7e e6 [2] 4c c4 [2] 4a f1 [2] 64 f1 [2] 5b ed }

  condition:
    any of them
}