rule TTP_XOR_WriteProcessMemory_3597 {
  strings:
    $key_3597 = { 62 e5 [2] 50 c7 [2] 56 f2 [2] 78 f2 [2] 47 ee }

  condition:
    any of them
}