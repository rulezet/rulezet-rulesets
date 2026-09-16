rule TTP_XOR_WriteProcessMemory_5ea7 {
  strings:
    $key_5ea7 = { 09 d5 [2] 3b f7 [2] 3d c2 [2] 13 c2 [2] 2c de }

  condition:
    any of them
}