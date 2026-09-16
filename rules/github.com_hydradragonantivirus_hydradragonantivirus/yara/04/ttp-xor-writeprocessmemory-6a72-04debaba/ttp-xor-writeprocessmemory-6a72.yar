rule TTP_XOR_WriteProcessMemory_6a72 {
  strings:
    $key_6a72 = { 3d 00 [2] 0f 22 [2] 09 17 [2] 27 17 [2] 18 0b }

  condition:
    any of them
}