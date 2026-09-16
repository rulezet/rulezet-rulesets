rule TTP_XOR_WriteProcessMemory_4f54 {
  strings:
    $key_4f54 = { 18 26 [2] 2a 04 [2] 2c 31 [2] 02 31 [2] 3d 2d }

  condition:
    any of them
}