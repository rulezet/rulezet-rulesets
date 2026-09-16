rule TTP_XOR_WriteProcessMemory_b292 {
  strings:
    $key_b292 = { e5 e0 [2] d7 c2 [2] d1 f7 [2] ff f7 [2] c0 eb }

  condition:
    any of them
}