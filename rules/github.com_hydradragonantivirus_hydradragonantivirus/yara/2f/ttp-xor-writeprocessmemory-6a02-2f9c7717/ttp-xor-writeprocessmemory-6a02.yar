rule TTP_XOR_WriteProcessMemory_6a02 {
  strings:
    $key_6a02 = { 3d 70 [2] 0f 52 [2] 09 67 [2] 27 67 [2] 18 7b }

  condition:
    any of them
}