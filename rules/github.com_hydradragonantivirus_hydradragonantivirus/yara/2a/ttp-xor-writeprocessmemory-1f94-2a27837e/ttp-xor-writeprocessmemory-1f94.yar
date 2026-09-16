rule TTP_XOR_WriteProcessMemory_1f94 {
  strings:
    $key_1f94 = { 48 e6 [2] 7a c4 [2] 7c f1 [2] 52 f1 [2] 6d ed }

  condition:
    any of them
}