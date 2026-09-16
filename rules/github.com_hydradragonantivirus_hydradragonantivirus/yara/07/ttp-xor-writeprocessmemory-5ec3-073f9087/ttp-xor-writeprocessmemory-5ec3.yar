rule TTP_XOR_WriteProcessMemory_5ec3 {
  strings:
    $key_5ec3 = { 09 b1 [2] 3b 93 [2] 3d a6 [2] 13 a6 [2] 2c ba }

  condition:
    any of them
}