rule TTP_XOR_WriteProcessMemory_7002 {
  strings:
    $key_7002 = { 27 70 [2] 15 52 [2] 13 67 [2] 3d 67 [2] 02 7b }

  condition:
    any of them
}