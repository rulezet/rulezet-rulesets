rule TTP_XOR_WriteProcessMemory_12e4 {
  strings:
    $key_12e4 = { 45 96 [2] 77 b4 [2] 71 81 [2] 5f 81 [2] 60 9d }

  condition:
    any of them
}