rule TTP_XOR_WriteProcessMemory_5314 {
  strings:
    $key_5314 = { 04 66 [2] 36 44 [2] 30 71 [2] 1e 71 [2] 21 6d }

  condition:
    any of them
}