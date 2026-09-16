rule TTP_XOR_WriteProcessMemory_b290 {
  strings:
    $key_b290 = { e5 e2 [2] d7 c0 [2] d1 f5 [2] ff f5 [2] c0 e9 }

  condition:
    any of them
}