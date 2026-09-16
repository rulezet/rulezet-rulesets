rule TTP_XOR_WriteProcessMemory_a485 {
  strings:
    $key_a485 = { f3 f7 [2] c1 d5 [2] c7 e0 [2] e9 e0 [2] d6 fc }

  condition:
    any of them
}