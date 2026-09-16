rule TTP_XOR_WriteProcessMemory_b5d5 {
  strings:
    $key_b5d5 = { e2 a7 [2] d0 85 [2] d6 b0 [2] f8 b0 [2] c7 ac }

  condition:
    any of them
}