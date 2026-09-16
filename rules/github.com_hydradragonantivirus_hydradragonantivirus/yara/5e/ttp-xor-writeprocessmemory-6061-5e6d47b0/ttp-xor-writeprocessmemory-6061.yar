rule TTP_XOR_WriteProcessMemory_6061 {
  strings:
    $key_6061 = { 37 13 [2] 05 31 [2] 03 04 [2] 2d 04 [2] 12 18 }

  condition:
    any of them
}