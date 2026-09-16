rule TTP_XOR_WriteProcessMemory_4f61 {
  strings:
    $key_4f61 = { 18 13 [2] 2a 31 [2] 2c 04 [2] 02 04 [2] 3d 18 }

  condition:
    any of them
}