rule TTP_XOR_WriteProcessMemory_4e65 {
  strings:
    $key_4e65 = { 19 17 [2] 2b 35 [2] 2d 00 [2] 03 00 [2] 3c 1c }

  condition:
    any of them
}