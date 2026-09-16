rule TTP_XOR_WriteProcessMemory_30e4 {
  strings:
    $key_30e4 = { 67 96 [2] 55 b4 [2] 53 81 [2] 7d 81 [2] 42 9d }

  condition:
    any of them
}