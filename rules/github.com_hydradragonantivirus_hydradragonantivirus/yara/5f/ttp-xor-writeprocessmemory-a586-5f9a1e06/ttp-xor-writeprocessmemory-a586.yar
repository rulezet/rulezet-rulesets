rule TTP_XOR_WriteProcessMemory_a586 {
  strings:
    $key_a586 = { f2 f4 [2] c0 d6 [2] c6 e3 [2] e8 e3 [2] d7 ff }

  condition:
    any of them
}