rule TTP_XOR_WriteProcessMemory_7044 {
  strings:
    $key_7044 = { 27 36 [2] 15 14 [2] 13 21 [2] 3d 21 [2] 02 3d }

  condition:
    any of them
}