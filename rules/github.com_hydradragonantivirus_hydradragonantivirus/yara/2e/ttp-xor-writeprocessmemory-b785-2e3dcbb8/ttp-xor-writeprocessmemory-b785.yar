rule TTP_XOR_WriteProcessMemory_b785 {
  strings:
    $key_b785 = { e0 f7 [2] d2 d5 [2] d4 e0 [2] fa e0 [2] c5 fc }

  condition:
    any of them
}