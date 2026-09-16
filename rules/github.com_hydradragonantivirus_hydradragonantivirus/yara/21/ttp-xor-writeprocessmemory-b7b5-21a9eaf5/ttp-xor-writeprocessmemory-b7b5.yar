rule TTP_XOR_WriteProcessMemory_b7b5 {
  strings:
    $key_b7b5 = { e0 c7 [2] d2 e5 [2] d4 d0 [2] fa d0 [2] c5 cc }

  condition:
    any of them
}