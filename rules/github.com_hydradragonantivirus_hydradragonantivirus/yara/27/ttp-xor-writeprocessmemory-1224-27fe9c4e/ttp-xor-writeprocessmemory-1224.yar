rule TTP_XOR_WriteProcessMemory_1224 {
  strings:
    $key_1224 = { 45 56 [2] 77 74 [2] 71 41 [2] 5f 41 [2] 60 5d }

  condition:
    any of them
}