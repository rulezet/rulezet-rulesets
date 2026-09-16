rule TTP_XOR_WriteProcessMemory_6f94 {
  strings:
    $key_6f94 = { 38 e6 [2] 0a c4 [2] 0c f1 [2] 22 f1 [2] 1d ed }

  condition:
    any of them
}