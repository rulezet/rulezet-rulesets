rule TTP_XOR_WriteProcessMemory_b190 {
  strings:
    $key_b190 = { e6 e2 [2] d4 c0 [2] d2 f5 [2] fc f5 [2] c3 e9 }

  condition:
    any of them
}