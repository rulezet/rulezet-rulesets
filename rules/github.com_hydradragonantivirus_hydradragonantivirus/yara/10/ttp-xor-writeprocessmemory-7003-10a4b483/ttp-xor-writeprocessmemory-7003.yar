rule TTP_XOR_WriteProcessMemory_7003 {
  strings:
    $key_7003 = { 27 71 [2] 15 53 [2] 13 66 [2] 3d 66 [2] 02 7a }

  condition:
    any of them
}