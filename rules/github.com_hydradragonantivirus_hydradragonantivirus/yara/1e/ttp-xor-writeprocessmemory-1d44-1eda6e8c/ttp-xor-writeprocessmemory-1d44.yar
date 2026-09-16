rule TTP_XOR_WriteProcessMemory_1d44 {
  strings:
    $key_1d44 = { 4a 36 [2] 78 14 [2] 7e 21 [2] 50 21 [2] 6f 3d }

  condition:
    any of them
}