rule TTP_XOR_WriteProcessMemory_5f17 {
  strings:
    $key_5f17 = { 08 65 [2] 3a 47 [2] 3c 72 [2] 12 72 [2] 2d 6e }

  condition:
    any of them
}