rule TTP_XOR_WriteProcessMemory_25a4 {
  strings:
    $key_25a4 = { 72 d6 [2] 40 f4 [2] 46 c1 [2] 68 c1 [2] 57 dd }

  condition:
    any of them
}