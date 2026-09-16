rule TTP_XOR_WriteProcessMemory_54a4 {
  strings:
    $key_54a4 = { 03 d6 [2] 31 f4 [2] 37 c1 [2] 19 c1 [2] 26 dd }

  condition:
    any of them
}