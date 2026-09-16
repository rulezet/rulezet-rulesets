rule TTP_XOR_WriteProcessMemory_4f40 {
  strings:
    $key_4f40 = { 18 32 [2] 2a 10 [2] 2c 25 [2] 02 25 [2] 3d 39 }

  condition:
    any of them
}