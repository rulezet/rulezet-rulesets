rule TTP_XOR_WriteProcessMemory_4e33 {
  strings:
    $key_4e33 = { 19 41 [2] 2b 63 [2] 2d 56 [2] 03 56 [2] 3c 4a }

  condition:
    any of them
}