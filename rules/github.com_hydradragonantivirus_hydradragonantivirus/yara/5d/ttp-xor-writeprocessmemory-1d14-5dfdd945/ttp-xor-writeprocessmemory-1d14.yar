rule TTP_XOR_WriteProcessMemory_1d14 {
  strings:
    $key_1d14 = { 4a 66 [2] 78 44 [2] 7e 71 [2] 50 71 [2] 6f 6d }

  condition:
    any of them
}