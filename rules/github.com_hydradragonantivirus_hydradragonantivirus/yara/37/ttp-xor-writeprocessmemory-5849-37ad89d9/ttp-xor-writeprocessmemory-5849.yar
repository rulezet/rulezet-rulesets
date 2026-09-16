rule TTP_XOR_WriteProcessMemory_5849 {
  strings:
    $key_5849 = { 0f 3b [2] 3d 19 [2] 3b 2c [2] 15 2c [2] 2a 30 }

  condition:
    any of them
}