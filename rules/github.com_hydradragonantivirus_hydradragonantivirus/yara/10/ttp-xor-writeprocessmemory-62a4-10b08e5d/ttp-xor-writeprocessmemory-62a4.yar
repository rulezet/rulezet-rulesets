rule TTP_XOR_WriteProcessMemory_62a4 {
  strings:
    $key_62a4 = { 35 d6 [2] 07 f4 [2] 01 c1 [2] 2f c1 [2] 10 dd }

  condition:
    any of them
}