rule TTP_XOR_WriteProcessMemory_5e29 {
  strings:
    $key_5e29 = { 09 5b [2] 3b 79 [2] 3d 4c [2] 13 4c [2] 2c 50 }

  condition:
    any of them
}