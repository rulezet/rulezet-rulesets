rule TTP_XOR_WriteProcessMemory_4844 {
  strings:
    $key_4844 = { 1f 36 [2] 2d 14 [2] 2b 21 [2] 05 21 [2] 3a 3d }

  condition:
    any of them
}