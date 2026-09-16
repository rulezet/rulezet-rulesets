rule TTP_XOR_WriteProcessMemory_3054 {
  strings:
    $key_3054 = { 67 26 [2] 55 04 [2] 53 31 [2] 7d 31 [2] 42 2d }

  condition:
    any of them
}