rule TTP_XOR_WriteProcessMemory_4e11 {
  strings:
    $key_4e11 = { 19 63 [2] 2b 41 [2] 2d 74 [2] 03 74 [2] 3c 68 }

  condition:
    any of them
}