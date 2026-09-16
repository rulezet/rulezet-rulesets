rule TTP_XOR_WriteProcessMemory_7063 {
  strings:
    $key_7063 = { 27 11 [2] 15 33 [2] 13 06 [2] 3d 06 [2] 02 1a }

  condition:
    any of them
}