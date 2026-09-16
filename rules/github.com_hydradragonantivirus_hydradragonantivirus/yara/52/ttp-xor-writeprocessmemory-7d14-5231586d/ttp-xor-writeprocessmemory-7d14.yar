rule TTP_XOR_WriteProcessMemory_7d14 {
  strings:
    $key_7d14 = { 2a 66 [2] 18 44 [2] 1e 71 [2] 30 71 [2] 0f 6d }

  condition:
    any of them
}