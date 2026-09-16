rule TTP_XOR_WriteProcessMemory_7074 {
  strings:
    $key_7074 = { 27 06 [2] 15 24 [2] 13 11 [2] 3d 11 [2] 02 0d }

  condition:
    any of them
}