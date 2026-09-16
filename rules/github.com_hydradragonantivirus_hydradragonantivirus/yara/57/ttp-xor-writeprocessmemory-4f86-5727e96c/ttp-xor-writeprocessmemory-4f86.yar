rule TTP_XOR_WriteProcessMemory_4f86 {
  strings:
    $key_4f86 = { 18 f4 [2] 2a d6 [2] 2c e3 [2] 02 e3 [2] 3d ff }

  condition:
    any of them
}