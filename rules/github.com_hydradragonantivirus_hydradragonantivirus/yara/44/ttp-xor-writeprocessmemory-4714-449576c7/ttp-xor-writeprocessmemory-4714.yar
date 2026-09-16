rule TTP_XOR_WriteProcessMemory_4714 {
  strings:
    $key_4714 = { 10 66 [2] 22 44 [2] 24 71 [2] 0a 71 [2] 35 6d }

  condition:
    any of them
}