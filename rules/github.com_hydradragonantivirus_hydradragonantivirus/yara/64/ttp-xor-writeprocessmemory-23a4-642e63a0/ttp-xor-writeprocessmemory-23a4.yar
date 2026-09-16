rule TTP_XOR_WriteProcessMemory_23a4 {
  strings:
    $key_23a4 = { 74 d6 [2] 46 f4 [2] 40 c1 [2] 6e c1 [2] 51 dd }

  condition:
    any of them
}