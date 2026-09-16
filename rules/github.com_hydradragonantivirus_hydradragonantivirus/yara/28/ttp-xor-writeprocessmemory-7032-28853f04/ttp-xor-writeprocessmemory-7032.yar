rule TTP_XOR_WriteProcessMemory_7032 {
  strings:
    $key_7032 = { 27 40 [2] 15 62 [2] 13 57 [2] 3d 57 [2] 02 4b }

  condition:
    any of them
}