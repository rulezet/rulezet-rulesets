rule TTP_XOR_WriteProcessMemory_a0c5 {
  strings:
    $key_a0c5 = { f7 b7 [2] c5 95 [2] c3 a0 [2] ed a0 [2] d2 bc }

  condition:
    any of them
}