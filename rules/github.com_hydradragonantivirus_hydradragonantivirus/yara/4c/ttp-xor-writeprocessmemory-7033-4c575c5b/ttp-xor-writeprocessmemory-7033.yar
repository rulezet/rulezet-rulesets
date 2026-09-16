rule TTP_XOR_WriteProcessMemory_7033 {
  strings:
    $key_7033 = { 27 41 [2] 15 63 [2] 13 56 [2] 3d 56 [2] 02 4a }

  condition:
    any of them
}