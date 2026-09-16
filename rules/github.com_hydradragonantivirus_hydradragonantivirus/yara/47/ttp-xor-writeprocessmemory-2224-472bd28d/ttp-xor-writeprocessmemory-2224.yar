rule TTP_XOR_WriteProcessMemory_2224 {
  strings:
    $key_2224 = { 75 56 [2] 47 74 [2] 41 41 [2] 6f 41 [2] 50 5d }

  condition:
    any of them
}