rule TTP_XOR_WriteProcessMemory_4fe7 {
  strings:
    $key_4fe7 = { 18 95 [2] 2a b7 [2] 2c 82 [2] 02 82 [2] 3d 9e }

  condition:
    any of them
}