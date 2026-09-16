rule TTP_XOR_WriteProcessMemory_7054 {
  strings:
    $key_7054 = { 27 26 [2] 15 04 [2] 13 31 [2] 3d 31 [2] 02 2d }

  condition:
    any of them
}