rule TTP_XOR_WriteProcessMemory_4fe9 {
  strings:
    $key_4fe9 = { 18 9b [2] 2a b9 [2] 2c 8c [2] 02 8c [2] 3d 90 }

  condition:
    any of them
}