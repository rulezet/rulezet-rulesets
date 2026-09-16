rule TTP_XOR_WriteProcessMemory_2254 {
  strings:
    $key_2254 = { 75 26 [2] 47 04 [2] 41 31 [2] 6f 31 [2] 50 2d }

  condition:
    any of them
}