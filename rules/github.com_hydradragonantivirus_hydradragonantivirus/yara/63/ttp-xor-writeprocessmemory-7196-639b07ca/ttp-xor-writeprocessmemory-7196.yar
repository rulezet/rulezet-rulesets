rule TTP_XOR_WriteProcessMemory_7196 {
  strings:
    $key_7196 = { 26 e4 [2] 14 c6 [2] 12 f3 [2] 3c f3 [2] 03 ef }

  condition:
    any of them
}