rule TTP_XOR_WriteProcessMemory_f5a4 {
  strings:
    $key_f5a4 = { a2 d6 [2] 90 f4 [2] 96 c1 [2] b8 c1 [2] 87 dd }

  condition:
    any of them
}