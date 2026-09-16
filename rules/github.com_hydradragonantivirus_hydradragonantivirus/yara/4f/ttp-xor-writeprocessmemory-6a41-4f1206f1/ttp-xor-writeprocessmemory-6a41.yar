rule TTP_XOR_WriteProcessMemory_6a41 {
  strings:
    $key_6a41 = { 3d 33 [2] 0f 11 [2] 09 24 [2] 27 24 [2] 18 38 }

  condition:
    any of them
}