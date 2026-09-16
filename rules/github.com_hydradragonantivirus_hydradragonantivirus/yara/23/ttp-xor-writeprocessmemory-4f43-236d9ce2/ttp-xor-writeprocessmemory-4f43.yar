rule TTP_XOR_WriteProcessMemory_4f43 {
  strings:
    $key_4f43 = { 18 31 [2] 2a 13 [2] 2c 26 [2] 02 26 [2] 3d 3a }

  condition:
    any of them
}