rule TTP_XOR_WriteProcessMemory_4f20 {
  strings:
    $key_4f20 = { 18 52 [2] 2a 70 [2] 2c 45 [2] 02 45 [2] 3d 59 }

  condition:
    any of them
}