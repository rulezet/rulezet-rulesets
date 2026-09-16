rule TTP_XOR_WriteProcessMemory_10e4 {
  strings:
    $key_10e4 = { 47 96 [2] 75 b4 [2] 73 81 [2] 5d 81 [2] 62 9d }

  condition:
    any of them
}