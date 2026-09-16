rule TTP_XOR_WriteProcessMemory_5ff1 {
  strings:
    $key_5ff1 = { 08 83 [2] 3a a1 [2] 3c 94 [2] 12 94 [2] 2d 88 }

  condition:
    any of them
}