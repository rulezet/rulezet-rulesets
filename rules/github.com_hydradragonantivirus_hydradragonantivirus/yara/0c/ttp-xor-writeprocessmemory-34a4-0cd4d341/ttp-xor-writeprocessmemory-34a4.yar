rule TTP_XOR_WriteProcessMemory_34a4 {
  strings:
    $key_34a4 = { 63 d6 [2] 51 f4 [2] 57 c1 [2] 79 c1 [2] 46 dd }

  condition:
    any of them
}