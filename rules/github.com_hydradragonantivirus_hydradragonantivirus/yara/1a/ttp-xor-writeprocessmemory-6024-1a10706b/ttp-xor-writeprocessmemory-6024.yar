rule TTP_XOR_WriteProcessMemory_6024 {
  strings:
    $key_6024 = { 37 56 [2] 05 74 [2] 03 41 [2] 2d 41 [2] 12 5d }

  condition:
    any of them
}