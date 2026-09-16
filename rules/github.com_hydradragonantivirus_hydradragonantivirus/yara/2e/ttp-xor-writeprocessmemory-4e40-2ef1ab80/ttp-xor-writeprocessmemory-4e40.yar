rule TTP_XOR_WriteProcessMemory_4e40 {
  strings:
    $key_4e40 = { 19 32 [2] 2b 10 [2] 2d 25 [2] 03 25 [2] 3c 39 }

  condition:
    any of them
}