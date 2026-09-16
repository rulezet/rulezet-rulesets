rule TTP_XOR_WriteProcessMemory_64a4 {
  strings:
    $key_64a4 = { 33 d6 [2] 01 f4 [2] 07 c1 [2] 29 c1 [2] 16 dd }

  condition:
    any of them
}