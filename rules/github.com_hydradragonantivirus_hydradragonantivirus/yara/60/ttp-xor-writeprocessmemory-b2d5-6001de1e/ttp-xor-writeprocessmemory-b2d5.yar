rule TTP_XOR_WriteProcessMemory_b2d5 {
  strings:
    $key_b2d5 = { e5 a7 [2] d7 85 [2] d1 b0 [2] ff b0 [2] c0 ac }

  condition:
    any of them
}