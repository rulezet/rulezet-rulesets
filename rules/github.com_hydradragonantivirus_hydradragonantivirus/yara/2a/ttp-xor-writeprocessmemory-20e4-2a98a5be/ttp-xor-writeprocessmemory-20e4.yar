rule TTP_XOR_WriteProcessMemory_20e4 {
  strings:
    $key_20e4 = { 77 96 [2] 45 b4 [2] 43 81 [2] 6d 81 [2] 52 9d }

  condition:
    any of them
}