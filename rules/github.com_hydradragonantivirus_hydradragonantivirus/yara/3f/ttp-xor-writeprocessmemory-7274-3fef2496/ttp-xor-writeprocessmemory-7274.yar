rule TTP_XOR_WriteProcessMemory_7274 {
  strings:
    $key_7274 = { 25 06 [2] 17 24 [2] 11 11 [2] 3f 11 [2] 00 0d }

  condition:
    any of them
}