rule TTP_XOR_WriteProcessMemory_b392 {
  strings:
    $key_b392 = { e4 e0 [2] d6 c2 [2] d0 f7 [2] fe f7 [2] c1 eb }

  condition:
    any of them
}