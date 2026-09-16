rule TTP_XOR_WriteProcessMemory_7244 {
  strings:
    $key_7244 = { 25 36 [2] 17 14 [2] 11 21 [2] 3f 21 [2] 00 3d }

  condition:
    any of them
}