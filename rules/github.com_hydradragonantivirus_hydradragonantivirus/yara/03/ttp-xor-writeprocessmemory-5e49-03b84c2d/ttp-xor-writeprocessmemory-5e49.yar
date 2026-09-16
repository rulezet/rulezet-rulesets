rule TTP_XOR_WriteProcessMemory_5e49 {
  strings:
    $key_5e49 = { 09 3b [2] 3b 19 [2] 3d 2c [2] 13 2c [2] 2c 30 }

  condition:
    any of them
}