rule TTP_XOR_WriteProcessMemory_4314 {
  strings:
    $key_4314 = { 14 66 [2] 26 44 [2] 20 71 [2] 0e 71 [2] 31 6d }

  condition:
    any of them
}