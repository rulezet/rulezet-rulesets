rule TTP_XOR_WriteProcessMemory_a686 {
  strings:
    $key_a686 = { f1 f4 [2] c3 d6 [2] c5 e3 [2] eb e3 [2] d4 ff }

  condition:
    any of them
}