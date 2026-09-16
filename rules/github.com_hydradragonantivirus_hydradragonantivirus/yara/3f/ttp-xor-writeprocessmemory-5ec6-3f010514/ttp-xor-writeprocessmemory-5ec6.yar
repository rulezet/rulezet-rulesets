rule TTP_XOR_WriteProcessMemory_5ec6 {
  strings:
    $key_5ec6 = { 09 b4 [2] 3b 96 [2] 3d a3 [2] 13 a3 [2] 2c bf }

  condition:
    any of them
}