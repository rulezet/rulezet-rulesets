rule TTP_XOR_WriteProcessMemory_5087 {
  strings:
    $key_5087 = { 07 f5 [2] 35 d7 [2] 33 e2 [2] 1d e2 [2] 22 fe }

  condition:
    any of them
}