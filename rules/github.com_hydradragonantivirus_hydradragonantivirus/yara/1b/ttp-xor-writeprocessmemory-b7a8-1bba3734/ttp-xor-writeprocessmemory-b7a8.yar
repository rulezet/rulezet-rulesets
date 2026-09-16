rule TTP_XOR_WriteProcessMemory_b7a8 {
  strings:
    $key_b7a8 = { e0 da [2] d2 f8 [2] d4 cd [2] fa cd [2] c5 d1 }

  condition:
    any of them
}