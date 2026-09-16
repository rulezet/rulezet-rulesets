rule TTP_XOR_WriteProcessMemory_5fe7 {
  strings:
    $key_5fe7 = { 08 95 [2] 3a b7 [2] 3c 82 [2] 12 82 [2] 2d 9e }

  condition:
    any of them
}