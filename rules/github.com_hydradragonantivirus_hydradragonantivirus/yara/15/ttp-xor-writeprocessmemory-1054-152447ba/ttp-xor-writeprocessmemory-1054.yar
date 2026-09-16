rule TTP_XOR_WriteProcessMemory_1054 {
  strings:
    $key_1054 = { 47 26 [2] 75 04 [2] 73 31 [2] 5d 31 [2] 62 2d }

  condition:
    any of them
}