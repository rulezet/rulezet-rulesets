rule TTP_XOR_WriteProcessMemory_02a4 {
  strings:
    $key_02a4 = { 55 d6 [2] 67 f4 [2] 61 c1 [2] 4f c1 [2] 70 dd }

  condition:
    any of them
}