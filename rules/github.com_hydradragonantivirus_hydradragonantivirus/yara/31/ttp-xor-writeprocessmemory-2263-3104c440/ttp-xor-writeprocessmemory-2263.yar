rule TTP_XOR_WriteProcessMemory_2263 {
  strings:
    $key_2263 = { 75 11 [2] 47 33 [2] 41 06 [2] 6f 06 [2] 50 1a }

  condition:
    any of them
}