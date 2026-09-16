rule TTP_XOR_WriteProcessMemory_0f94 {
  strings:
    $key_0f94 = { 58 e6 [2] 6a c4 [2] 6c f1 [2] 42 f1 [2] 7d ed }

  condition:
    any of them
}