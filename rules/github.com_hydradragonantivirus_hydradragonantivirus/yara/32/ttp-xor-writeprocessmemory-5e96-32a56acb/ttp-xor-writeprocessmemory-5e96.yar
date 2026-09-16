rule TTP_XOR_WriteProcessMemory_5e96 {
  strings:
    $key_5e96 = { 09 e4 [2] 3b c6 [2] 3d f3 [2] 13 f3 [2] 2c ef }

  condition:
    any of them
}