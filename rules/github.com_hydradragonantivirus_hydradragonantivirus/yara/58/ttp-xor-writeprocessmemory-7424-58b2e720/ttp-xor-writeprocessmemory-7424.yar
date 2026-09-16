rule TTP_XOR_WriteProcessMemory_7424 {
  strings:
    $key_7424 = { 23 56 [2] 11 74 [2] 17 41 [2] 39 41 [2] 06 5d }

  condition:
    any of them
}