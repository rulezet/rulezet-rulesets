rule TTP_XOR_WriteProcessMemory_7067 {
  strings:
    $key_7067 = { 27 15 [2] 15 37 [2] 13 02 [2] 3d 02 [2] 02 1e }

  condition:
    any of them
}