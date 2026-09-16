rule TTP_XOR_WriteProcessMemory_4e26 {
  strings:
    $key_4e26 = { 19 54 [2] 2b 76 [2] 2d 43 [2] 03 43 [2] 3c 5f }

  condition:
    any of them
}