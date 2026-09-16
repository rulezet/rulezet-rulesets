rule TTP_XOR_WriteProcessMemory_4fc3 {
  strings:
    $key_4fc3 = { 18 b1 [2] 2a 93 [2] 2c a6 [2] 02 a6 [2] 3d ba }

  condition:
    any of them
}