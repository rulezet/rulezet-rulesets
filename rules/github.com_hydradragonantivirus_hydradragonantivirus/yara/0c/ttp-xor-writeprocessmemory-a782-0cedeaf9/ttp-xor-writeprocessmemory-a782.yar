rule TTP_XOR_WriteProcessMemory_a782 {
  strings:
    $key_a782 = { f0 f0 [2] c2 d2 [2] c4 e7 [2] ea e7 [2] d5 fb }

  condition:
    any of them
}