rule TTP_XOR_WriteProcessMemory_3196 {
  strings:
    $key_3196 = { 66 e4 [2] 54 c6 [2] 52 f3 [2] 7c f3 [2] 43 ef }

  condition:
    any of them
}