rule TTP_XOR_WriteProcessMemory_64e1 {
  strings:
    $key_64e1 = { 33 93 [2] 01 b1 [2] 07 84 [2] 29 84 [2] 16 98 }

  condition:
    any of them
}