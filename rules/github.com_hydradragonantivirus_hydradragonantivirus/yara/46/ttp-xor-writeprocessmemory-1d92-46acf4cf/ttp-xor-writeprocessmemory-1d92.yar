rule TTP_XOR_WriteProcessMemory_1d92 {
  strings:
    $key_1d92 = { 4a e0 [2] 78 c2 [2] 7e f7 [2] 50 f7 [2] 6f eb }

  condition:
    any of them
}