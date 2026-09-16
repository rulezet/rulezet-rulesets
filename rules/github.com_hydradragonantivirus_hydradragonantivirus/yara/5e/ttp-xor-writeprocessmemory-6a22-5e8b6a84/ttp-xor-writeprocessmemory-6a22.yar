rule TTP_XOR_WriteProcessMemory_6a22 {
  strings:
    $key_6a22 = { 3d 50 [2] 0f 72 [2] 09 47 [2] 27 47 [2] 18 5b }

  condition:
    any of them
}