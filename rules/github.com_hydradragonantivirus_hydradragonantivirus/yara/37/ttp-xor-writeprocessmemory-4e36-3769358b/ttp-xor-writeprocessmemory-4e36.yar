rule TTP_XOR_WriteProcessMemory_4e36 {
  strings:
    $key_4e36 = { 19 44 [2] 2b 66 [2] 2d 53 [2] 03 53 [2] 3c 4f }

  condition:
    any of them
}