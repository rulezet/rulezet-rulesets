rule TTP_XOR_WriteProcessMemory_4843 {
  strings:
    $key_4843 = { 1f 31 [2] 2d 13 [2] 2b 26 [2] 05 26 [2] 3a 3a }

  condition:
    any of them
}