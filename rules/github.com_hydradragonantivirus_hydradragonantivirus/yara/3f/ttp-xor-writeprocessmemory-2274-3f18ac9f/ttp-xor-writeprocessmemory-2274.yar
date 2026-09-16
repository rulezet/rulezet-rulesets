rule TTP_XOR_WriteProcessMemory_2274 {
  strings:
    $key_2274 = { 75 06 [2] 47 24 [2] 41 11 [2] 6f 11 [2] 50 0d }

  condition:
    any of them
}