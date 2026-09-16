rule TTP_XOR_WriteProcessMemory_4e02 {
  strings:
    $key_4e02 = { 19 70 [2] 2b 52 [2] 2d 67 [2] 03 67 [2] 3c 7b }

  condition:
    any of them
}