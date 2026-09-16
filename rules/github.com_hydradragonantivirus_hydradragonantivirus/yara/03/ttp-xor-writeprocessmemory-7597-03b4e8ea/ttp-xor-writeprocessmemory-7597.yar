rule TTP_XOR_WriteProcessMemory_7597 {
  strings:
    $key_7597 = { 22 e5 [2] 10 c7 [2] 16 f2 [2] 38 f2 [2] 07 ee }

  condition:
    any of them
}