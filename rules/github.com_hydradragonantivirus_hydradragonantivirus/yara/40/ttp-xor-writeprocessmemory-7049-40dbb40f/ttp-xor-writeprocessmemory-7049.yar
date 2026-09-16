rule TTP_XOR_WriteProcessMemory_7049 {
  strings:
    $key_7049 = { 27 3b [2] 15 19 [2] 13 2c [2] 3d 2c [2] 02 30 }

  condition:
    any of them
}