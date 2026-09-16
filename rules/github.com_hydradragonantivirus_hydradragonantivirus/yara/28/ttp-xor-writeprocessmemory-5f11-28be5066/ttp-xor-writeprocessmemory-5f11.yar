rule TTP_XOR_WriteProcessMemory_5f11 {
  strings:
    $key_5f11 = { 08 63 [2] 3a 41 [2] 3c 74 [2] 12 74 [2] 2d 68 }

  condition:
    any of them
}