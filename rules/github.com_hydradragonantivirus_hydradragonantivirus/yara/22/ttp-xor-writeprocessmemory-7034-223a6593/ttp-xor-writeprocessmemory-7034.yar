rule TTP_XOR_WriteProcessMemory_7034 {
  strings:
    $key_7034 = { 27 46 [2] 15 64 [2] 13 51 [2] 3d 51 [2] 02 4d }

  condition:
    any of them
}