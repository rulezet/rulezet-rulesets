rule TTP_XOR_WriteProcessMemory_5f34 {
  strings:
    $key_5f34 = { 08 46 [2] 3a 64 [2] 3c 51 [2] 12 51 [2] 2d 4d }

  condition:
    any of them
}