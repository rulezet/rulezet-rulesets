rule TTP_XOR_WriteProcessMemory_7030 {
  strings:
    $key_7030 = { 27 42 [2] 15 60 [2] 13 55 [2] 3d 55 [2] 02 49 }

  condition:
    any of them
}