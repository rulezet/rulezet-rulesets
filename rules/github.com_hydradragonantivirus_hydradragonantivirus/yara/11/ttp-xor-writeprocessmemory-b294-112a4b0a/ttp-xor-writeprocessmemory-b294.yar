rule TTP_XOR_WriteProcessMemory_b294 {
  strings:
    $key_b294 = { e5 e6 [2] d7 c4 [2] d1 f1 [2] ff f1 [2] c0 ed }

  condition:
    any of them
}