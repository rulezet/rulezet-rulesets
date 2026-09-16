rule TTP_XOR_WriteProcessMemory_5e03 {
  strings:
    $key_5e03 = { 09 71 [2] 3b 53 [2] 3d 66 [2] 13 66 [2] 2c 7a }

  condition:
    any of them
}