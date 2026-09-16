rule TTP_XOR_WriteProcessMemory_3266 {
  strings:
    $key_3266 = { 65 14 [2] 57 36 [2] 51 03 [2] 7f 03 [2] 40 1f }

  condition:
    any of them
}