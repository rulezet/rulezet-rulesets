rule TTP_XOR_WriteProcessMemory_52a4 {
  strings:
    $key_52a4 = { 05 d6 [2] 37 f4 [2] 31 c1 [2] 1f c1 [2] 20 dd }

  condition:
    any of them
}