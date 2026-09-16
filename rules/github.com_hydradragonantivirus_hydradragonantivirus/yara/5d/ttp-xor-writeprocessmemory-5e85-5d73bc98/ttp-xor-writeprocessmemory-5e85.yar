rule TTP_XOR_WriteProcessMemory_5e85 {
  strings:
    $key_5e85 = { 09 f7 [2] 3b d5 [2] 3d e0 [2] 13 e0 [2] 2c fc }

  condition:
    any of them
}