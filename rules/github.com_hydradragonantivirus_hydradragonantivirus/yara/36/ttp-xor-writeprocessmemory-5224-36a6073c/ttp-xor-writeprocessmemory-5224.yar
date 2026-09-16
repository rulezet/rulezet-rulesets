rule TTP_XOR_WriteProcessMemory_5224 {
  strings:
    $key_5224 = { 05 56 [2] 37 74 [2] 31 41 [2] 1f 41 [2] 20 5d }

  condition:
    any of them
}