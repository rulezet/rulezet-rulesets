rule TTP_XOR_WriteProcessMemory_0754 {
  strings:
    $key_0754 = { 50 26 [2] 62 04 [2] 64 31 [2] 4a 31 [2] 75 2d }

  condition:
    any of them
}