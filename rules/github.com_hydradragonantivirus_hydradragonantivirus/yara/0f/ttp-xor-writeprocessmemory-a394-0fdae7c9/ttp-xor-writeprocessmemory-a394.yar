rule TTP_XOR_WriteProcessMemory_a394 {
  strings:
    $key_a394 = { f4 e6 [2] c6 c4 [2] c0 f1 [2] ee f1 [2] d1 ed }

  condition:
    any of them
}