rule TTP_XOR_WriteProcessMemory_4fc4 {
  strings:
    $key_4fc4 = { 18 b6 [2] 2a 94 [2] 2c a1 [2] 02 a1 [2] 3d bd }

  condition:
    any of them
}