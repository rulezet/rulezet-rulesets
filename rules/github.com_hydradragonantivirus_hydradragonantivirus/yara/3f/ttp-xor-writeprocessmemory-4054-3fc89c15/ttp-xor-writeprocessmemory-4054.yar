rule TTP_XOR_WriteProcessMemory_4054 {
  strings:
    $key_4054 = { 17 26 [2] 25 04 [2] 23 31 [2] 0d 31 [2] 32 2d }

  condition:
    any of them
}