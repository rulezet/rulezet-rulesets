rule TTP_XOR_WriteProcessMemory_4f84 {
  strings:
    $key_4f84 = { 18 f6 [2] 2a d4 [2] 2c e1 [2] 02 e1 [2] 3d fd }

  condition:
    any of them
}