rule TTP_XOR_WriteProcessMemory_7da2 {
  strings:
    $key_7da2 = { 2a d0 [2] 18 f2 [2] 1e c7 [2] 30 c7 [2] 0f db }

  condition:
    any of them
}