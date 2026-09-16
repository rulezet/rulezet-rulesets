rule TTP_XOR_WriteProcessMemory_4e51 {
  strings:
    $key_4e51 = { 19 23 [2] 2b 01 [2] 2d 34 [2] 03 34 [2] 3c 28 }

  condition:
    any of them
}