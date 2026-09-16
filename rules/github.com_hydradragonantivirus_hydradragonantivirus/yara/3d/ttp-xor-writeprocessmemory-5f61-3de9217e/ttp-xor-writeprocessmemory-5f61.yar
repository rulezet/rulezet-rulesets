rule TTP_XOR_WriteProcessMemory_5f61 {
  strings:
    $key_5f61 = { 08 13 [2] 3a 31 [2] 3c 04 [2] 12 04 [2] 2d 18 }

  condition:
    any of them
}