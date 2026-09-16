rule TTP_XOR_WriteProcessMemory_1244 {
  strings:
    $key_1244 = { 45 36 [2] 77 14 [2] 71 21 [2] 5f 21 [2] 60 3d }

  condition:
    any of them
}