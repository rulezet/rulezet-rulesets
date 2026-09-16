rule TTP_XOR_WriteProcessMemory_50e4 {
  strings:
    $key_50e4 = { 07 96 [2] 35 b4 [2] 33 81 [2] 1d 81 [2] 22 9d }

  condition:
    any of them
}