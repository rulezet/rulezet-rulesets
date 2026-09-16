rule TTP_XOR_WriteProcessMemory_3fe7 {
  strings:
    $key_3fe7 = { 68 95 [2] 5a b7 [2] 5c 82 [2] 72 82 [2] 4d 9e }

  condition:
    any of them
}