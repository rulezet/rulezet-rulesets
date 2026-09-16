rule TTP_XOR_WriteProcessMemory_6a63 {
  strings:
    $key_6a63 = { 3d 11 [2] 0f 33 [2] 09 06 [2] 27 06 [2] 18 1a }

  condition:
    any of them
}