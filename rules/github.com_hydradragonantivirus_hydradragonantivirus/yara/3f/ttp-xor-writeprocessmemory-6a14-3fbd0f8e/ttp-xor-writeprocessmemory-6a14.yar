rule TTP_XOR_WriteProcessMemory_6a14 {
  strings:
    $key_6a14 = { 3d 66 [2] 0f 44 [2] 09 71 [2] 27 71 [2] 18 6d }

  condition:
    any of them
}