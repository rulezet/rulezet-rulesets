rule TTP_XOR_WriteProcessMemory_6314 {
  strings:
    $key_6314 = { 34 66 [2] 06 44 [2] 00 71 [2] 2e 71 [2] 11 6d }

  condition:
    any of them
}