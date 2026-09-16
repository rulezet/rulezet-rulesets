rule TTP_XOR_WriteProcessMemory_1314 {
  strings:
    $key_1314 = { 44 66 [2] 76 44 [2] 70 71 [2] 5e 71 [2] 61 6d }

  condition:
    any of them
}