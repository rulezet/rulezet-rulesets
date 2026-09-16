rule TTP_XOR_WriteProcessMemory_4e71 {
  strings:
    $key_4e71 = { 19 03 [2] 2b 21 [2] 2d 14 [2] 03 14 [2] 3c 08 }

  condition:
    any of them
}