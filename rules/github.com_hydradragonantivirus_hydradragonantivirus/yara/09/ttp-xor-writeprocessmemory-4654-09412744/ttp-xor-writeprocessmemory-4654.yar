rule TTP_XOR_WriteProcessMemory_4654 {
  strings:
    $key_4654 = { 11 26 [2] 23 04 [2] 25 31 [2] 0b 31 [2] 34 2d }

  condition:
    any of them
}