rule TTP_XOR_WriteProcessMemory_72a4 {
  strings:
    $key_72a4 = { 25 d6 [2] 17 f4 [2] 11 c1 [2] 3f c1 [2] 00 dd }

  condition:
    any of them
}