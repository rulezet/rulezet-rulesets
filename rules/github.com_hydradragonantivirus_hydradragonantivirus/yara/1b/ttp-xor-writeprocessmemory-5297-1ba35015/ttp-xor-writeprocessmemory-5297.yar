rule TTP_XOR_WriteProcessMemory_5297 {
  strings:
    $key_5297 = { 05 e5 [2] 37 c7 [2] 31 f2 [2] 1f f2 [2] 20 ee }

  condition:
    any of them
}