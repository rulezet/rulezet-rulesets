rule TTP_XOR_WriteProcessMemory_6087 {
  strings:
    $key_6087 = { 37 f5 [2] 05 d7 [2] 03 e2 [2] 2d e2 [2] 12 fe }

  condition:
    any of them
}