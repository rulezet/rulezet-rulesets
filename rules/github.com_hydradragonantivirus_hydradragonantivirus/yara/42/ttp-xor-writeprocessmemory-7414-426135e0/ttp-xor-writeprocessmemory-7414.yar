rule TTP_XOR_WriteProcessMemory_7414 {
  strings:
    $key_7414 = { 23 66 [2] 11 44 [2] 17 71 [2] 39 71 [2] 06 6d }

  condition:
    any of them
}