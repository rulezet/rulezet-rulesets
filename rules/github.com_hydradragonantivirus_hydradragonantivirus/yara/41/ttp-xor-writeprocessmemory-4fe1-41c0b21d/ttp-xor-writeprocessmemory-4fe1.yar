rule TTP_XOR_WriteProcessMemory_4fe1 {
  strings:
    $key_4fe1 = { 18 93 [2] 2a b1 [2] 2c 84 [2] 02 84 [2] 3d 98 }

  condition:
    any of them
}