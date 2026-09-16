rule TTP_XOR_WriteProcessMemory_4f44 {
  strings:
    $key_4f44 = { 18 36 [2] 2a 14 [2] 2c 21 [2] 02 21 [2] 3d 3d }

  condition:
    any of them
}