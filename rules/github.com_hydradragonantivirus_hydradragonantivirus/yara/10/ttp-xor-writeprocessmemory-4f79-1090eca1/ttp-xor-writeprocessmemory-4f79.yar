rule TTP_XOR_WriteProcessMemory_4f79 {
  strings:
    $key_4f79 = { 18 0b [2] 2a 29 [2] 2c 1c [2] 02 1c [2] 3d 00 }

  condition:
    any of them
}