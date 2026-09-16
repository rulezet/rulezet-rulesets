rule TTP_XOR_WriteProcessMemory_6e71 {
  strings:
    $key_6e71 = { 39 03 [2] 0b 21 [2] 0d 14 [2] 23 14 [2] 1c 08 }

  condition:
    any of them
}