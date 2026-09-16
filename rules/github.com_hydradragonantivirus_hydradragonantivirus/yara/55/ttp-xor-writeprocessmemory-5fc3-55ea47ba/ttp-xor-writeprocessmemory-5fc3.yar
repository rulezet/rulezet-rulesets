rule TTP_XOR_WriteProcessMemory_5fc3 {
  strings:
    $key_5fc3 = { 08 b1 [2] 3a 93 [2] 3c a6 [2] 12 a6 [2] 2d ba }

  condition:
    any of them
}