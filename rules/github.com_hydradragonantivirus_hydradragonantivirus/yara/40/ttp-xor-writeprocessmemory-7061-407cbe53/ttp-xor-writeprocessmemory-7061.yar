rule TTP_XOR_WriteProcessMemory_7061 {
  strings:
    $key_7061 = { 27 13 [2] 15 31 [2] 13 04 [2] 3d 04 [2] 02 18 }

  condition:
    any of them
}