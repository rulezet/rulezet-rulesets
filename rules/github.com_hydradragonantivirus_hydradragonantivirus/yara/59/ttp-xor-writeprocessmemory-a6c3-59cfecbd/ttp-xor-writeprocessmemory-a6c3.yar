rule TTP_XOR_WriteProcessMemory_a6c3 {
  strings:
    $key_a6c3 = { f1 b1 [2] c3 93 [2] c5 a6 [2] eb a6 [2] d4 ba }

  condition:
    any of them
}