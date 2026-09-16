rule TTP_XOR_WriteProcessMemory_6851 {
  strings:
    $key_6851 = { 3f 23 [2] 0d 01 [2] 0b 34 [2] 25 34 [2] 1a 28 }

  condition:
    any of them
}