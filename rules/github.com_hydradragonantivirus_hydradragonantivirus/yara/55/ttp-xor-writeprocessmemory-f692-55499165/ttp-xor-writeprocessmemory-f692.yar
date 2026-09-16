rule TTP_XOR_WriteProcessMemory_f692 {
  strings:
    $key_f692 = { a1 e0 [2] 93 c2 [2] 95 f7 [2] bb f7 [2] 84 eb }

  condition:
    any of them
}