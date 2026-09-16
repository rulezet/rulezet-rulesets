rule TTP_XOR_WriteProcessMemory_4597 {
  strings:
    $key_4597 = { 12 e5 [2] 20 c7 [2] 26 f2 [2] 08 f2 [2] 37 ee }

  condition:
    any of them
}