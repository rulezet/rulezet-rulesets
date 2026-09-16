rule TTP_XOR_WriteProcessMemory_4e76 {
  strings:
    $key_4e76 = { 19 04 [2] 2b 26 [2] 2d 13 [2] 03 13 [2] 3c 0f }

  condition:
    any of them
}