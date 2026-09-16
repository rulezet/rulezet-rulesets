rule TTP_XOR_WriteProcessMemory_4f06 {
  strings:
    $key_4f06 = { 18 74 [2] 2a 56 [2] 2c 63 [2] 02 63 [2] 3d 7f }

  condition:
    any of them
}