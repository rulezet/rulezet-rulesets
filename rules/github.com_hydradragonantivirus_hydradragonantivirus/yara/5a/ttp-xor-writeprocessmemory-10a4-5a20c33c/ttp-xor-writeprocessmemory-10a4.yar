rule TTP_XOR_WriteProcessMemory_10a4 {
  strings:
    $key_10a4 = { 47 d6 [2] 75 f4 [2] 73 c1 [2] 5d c1 [2] 62 dd }

  condition:
    any of them
}