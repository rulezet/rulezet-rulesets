rule TTP_XOR_WriteProcessMemory_5f10 {
  strings:
    $key_5f10 = { 08 62 [2] 3a 40 [2] 3c 75 [2] 12 75 [2] 2d 69 }

  condition:
    any of them
}