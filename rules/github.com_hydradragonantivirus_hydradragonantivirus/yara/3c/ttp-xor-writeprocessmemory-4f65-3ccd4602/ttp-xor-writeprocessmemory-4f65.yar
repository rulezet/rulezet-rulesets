rule TTP_XOR_WriteProcessMemory_4f65 {
  strings:
    $key_4f65 = { 18 17 [2] 2a 35 [2] 2c 00 [2] 02 00 [2] 3d 1c }

  condition:
    any of them
}