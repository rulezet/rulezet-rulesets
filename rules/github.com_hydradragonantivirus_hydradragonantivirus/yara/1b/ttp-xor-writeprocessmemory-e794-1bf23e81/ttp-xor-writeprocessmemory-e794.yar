rule TTP_XOR_WriteProcessMemory_e794 {
  strings:
    $key_e794 = { b0 e6 [2] 82 c4 [2] 84 f1 [2] aa f1 [2] 95 ed }

  condition:
    any of them
}