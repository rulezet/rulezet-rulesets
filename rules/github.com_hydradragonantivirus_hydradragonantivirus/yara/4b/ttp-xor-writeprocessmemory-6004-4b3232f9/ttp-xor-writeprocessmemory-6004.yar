rule TTP_XOR_WriteProcessMemory_6004 {
  strings:
    $key_6004 = { 37 76 [2] 05 54 [2] 03 61 [2] 2d 61 [2] 12 7d }

  condition:
    any of them
}