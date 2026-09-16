rule TTP_XOR_WriteProcessMemory_23b3 {
  strings:
    $key_23b3 = { 74 c1 [2] 46 e3 [2] 40 d6 [2] 6e d6 [2] 51 ca }

  condition:
    any of them
}