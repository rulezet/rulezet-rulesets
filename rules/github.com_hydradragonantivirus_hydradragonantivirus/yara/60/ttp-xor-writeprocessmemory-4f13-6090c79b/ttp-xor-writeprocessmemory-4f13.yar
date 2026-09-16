rule TTP_XOR_WriteProcessMemory_4f13 {
  strings:
    $key_4f13 = { 18 61 [2] 2a 43 [2] 2c 76 [2] 02 76 [2] 3d 6a }

  condition:
    any of them
}