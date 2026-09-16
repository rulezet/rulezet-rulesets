rule TTP_XOR_WriteProcessMemory_5ec1 {
  strings:
    $key_5ec1 = { 09 b3 [2] 3b 91 [2] 3d a4 [2] 13 a4 [2] 2c b8 }

  condition:
    any of them
}