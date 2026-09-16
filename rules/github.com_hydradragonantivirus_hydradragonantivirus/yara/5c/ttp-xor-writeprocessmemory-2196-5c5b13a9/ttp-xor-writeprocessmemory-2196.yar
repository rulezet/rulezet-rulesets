rule TTP_XOR_WriteProcessMemory_2196 {
  strings:
    $key_2196 = { 76 e4 [2] 44 c6 [2] 42 f3 [2] 6c f3 [2] 53 ef }

  condition:
    any of them
}