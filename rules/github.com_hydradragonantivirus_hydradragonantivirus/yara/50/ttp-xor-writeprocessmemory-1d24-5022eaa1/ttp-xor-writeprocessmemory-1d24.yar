rule TTP_XOR_WriteProcessMemory_1d24 {
  strings:
    $key_1d24 = { 4a 56 [2] 78 74 [2] 7e 41 [2] 50 41 [2] 6f 5d }

  condition:
    any of them
}