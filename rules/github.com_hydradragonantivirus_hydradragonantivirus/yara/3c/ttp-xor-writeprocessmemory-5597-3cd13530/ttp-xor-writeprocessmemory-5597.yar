rule TTP_XOR_WriteProcessMemory_5597 {
  strings:
    $key_5597 = { 02 e5 [2] 30 c7 [2] 36 f2 [2] 18 f2 [2] 27 ee }

  condition:
    any of them
}