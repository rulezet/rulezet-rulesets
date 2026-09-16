rule TTP_XOR_WriteProcessMemory_3190 {
  strings:
    $key_3190 = { 66 e2 [2] 54 c0 [2] 52 f5 [2] 7c f5 [2] 43 e9 }

  condition:
    any of them
}