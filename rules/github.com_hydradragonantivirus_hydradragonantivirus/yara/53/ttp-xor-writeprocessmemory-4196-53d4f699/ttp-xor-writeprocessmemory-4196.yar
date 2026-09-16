rule TTP_XOR_WriteProcessMemory_4196 {
  strings:
    $key_4196 = { 16 e4 [2] 24 c6 [2] 22 f3 [2] 0c f3 [2] 33 ef }

  condition:
    any of them
}