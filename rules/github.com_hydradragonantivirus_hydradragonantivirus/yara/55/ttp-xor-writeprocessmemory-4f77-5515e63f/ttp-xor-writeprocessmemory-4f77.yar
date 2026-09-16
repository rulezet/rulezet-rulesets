rule TTP_XOR_WriteProcessMemory_4f77 {
  strings:
    $key_4f77 = { 18 05 [2] 2a 27 [2] 2c 12 [2] 02 12 [2] 3d 0e }

  condition:
    any of them
}