rule TTP_XOR_WriteProcessMemory_b197 {
  strings:
    $key_b197 = { e6 e5 [2] d4 c7 [2] d2 f2 [2] fc f2 [2] c3 ee }

  condition:
    any of them
}