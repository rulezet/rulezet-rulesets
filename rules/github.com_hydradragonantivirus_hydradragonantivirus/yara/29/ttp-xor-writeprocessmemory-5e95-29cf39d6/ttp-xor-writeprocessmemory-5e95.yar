rule TTP_XOR_WriteProcessMemory_5e95 {
  strings:
    $key_5e95 = { 09 e7 [2] 3b c5 [2] 3d f0 [2] 13 f0 [2] 2c ec }

  condition:
    any of them
}