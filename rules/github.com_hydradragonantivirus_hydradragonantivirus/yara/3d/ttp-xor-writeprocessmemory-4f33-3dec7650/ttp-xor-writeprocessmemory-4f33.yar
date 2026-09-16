rule TTP_XOR_WriteProcessMemory_4f33 {
  strings:
    $key_4f33 = { 18 41 [2] 2a 63 [2] 2c 56 [2] 02 56 [2] 3d 4a }

  condition:
    any of them
}