rule TTP_XOR_WriteProcessMemory_5ef1 {
  strings:
    $key_5ef1 = { 09 83 [2] 3b a1 [2] 3d 94 [2] 13 94 [2] 2c 88 }

  condition:
    any of them
}