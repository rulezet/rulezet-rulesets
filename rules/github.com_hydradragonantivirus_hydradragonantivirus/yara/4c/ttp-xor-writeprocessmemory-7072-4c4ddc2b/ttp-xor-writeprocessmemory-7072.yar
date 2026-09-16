rule TTP_XOR_WriteProcessMemory_7072 {
  strings:
    $key_7072 = { 27 00 [2] 15 22 [2] 13 17 [2] 3d 17 [2] 02 0b }

  condition:
    any of them
}