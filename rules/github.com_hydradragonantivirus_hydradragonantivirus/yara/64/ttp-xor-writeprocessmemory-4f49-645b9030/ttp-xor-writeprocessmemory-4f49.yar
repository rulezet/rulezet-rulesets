rule TTP_XOR_WriteProcessMemory_4f49 {
  strings:
    $key_4f49 = { 18 3b [2] 2a 19 [2] 2c 2c [2] 02 2c [2] 3d 30 }

  condition:
    any of them
}