rule TTP_XOR_WriteProcessMemory_4e20 {
  strings:
    $key_4e20 = { 19 52 [2] 2b 70 [2] 2d 45 [2] 03 45 [2] 3c 59 }

  condition:
    any of them
}