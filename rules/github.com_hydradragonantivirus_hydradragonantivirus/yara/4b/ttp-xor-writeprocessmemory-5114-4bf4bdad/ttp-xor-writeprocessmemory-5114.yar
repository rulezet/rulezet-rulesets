rule TTP_XOR_WriteProcessMemory_5114 {
  strings:
    $key_5114 = { 06 66 [2] 34 44 [2] 32 71 [2] 1c 71 [2] 23 6d }

  condition:
    any of them
}