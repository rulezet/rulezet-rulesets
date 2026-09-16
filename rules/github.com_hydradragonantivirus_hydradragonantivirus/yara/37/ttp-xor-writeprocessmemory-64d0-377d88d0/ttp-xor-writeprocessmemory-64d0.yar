rule TTP_XOR_WriteProcessMemory_64d0 {
  strings:
    $key_64d0 = { 33 a2 [2] 01 80 [2] 07 b5 [2] 29 b5 [2] 16 a9 }

  condition:
    any of them
}